"""Target discovery: running Docker containers, Kubernetes pods, filesystem paths."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from config import Settings

logger = logging.getLogger(__name__)

_DIGEST_RE = re.compile(r"(sha256:[0-9a-f]{64})")


# ── Docker ────────────────────────────────────────────────────────────────────

_warned_containers: set[str] = set()


def _warn_once(container_name: str, message: str) -> None:
    """One warning per container and message, so a broken container does not flood the log every tick."""
    key = f"{container_name}:{message}"
    if key not in _warned_containers:
        _warned_containers.add(key)
        logger.warning(f"container {container_name}: {message}")


def _resolve_image(client, container):
    """The image object of a running container, or None when its image is no longer in the local daemon.

    A container can outlive its image (the tag was moved by a rebuild and the old layers were pruned). Looking up
    ``container.image`` then raises ImageNotFound. Fall back to the image name from the container's config, which
    is what Syft can still scan, and give up on this one container instead of the whole inventory.
    """
    try:
        return container.image
    except Exception:  # noqa: BLE001 - docker.errors.ImageNotFound and API errors
        pass
    name = (container.attrs.get("Config") or {}).get("Image")
    if name:
        try:
            return client.images.get(name)
        except Exception:  # noqa: BLE001
            pass
    return None


def get_running_docker_inventory() -> dict[str, Optional[str]]:
    """{image tag (or short id): full image id} for all running containers.

    Raises on Docker daemon errors. A single container whose image is gone is skipped with a warning.
    """
    import docker

    client = docker.from_env()
    inventory: dict[str, Optional[str]] = {}
    for container in client.containers.list():
        image = _resolve_image(client, container)
        if image is None:
            _warn_once(container.name, "image is no longer available locally, skipped "
                                       "(recreate the container to scan it)")
            continue
        tag = image.tags[0] if image.tags else image.short_id
        inventory.setdefault(tag, image.id)
    return inventory


def get_running_docker_images() -> list[str]:
    try:
        return list(get_running_docker_inventory().keys())
    except Exception as e:  # noqa: BLE001 - Docker SDK raises many exception types
        logger.error(f"Docker API error: {e}")
        return []


def get_docker_image_id(image: str) -> Optional[str]:
    """Local image id for a tag, or None when the image is not present in the local daemon."""
    try:
        import docker

        return docker.from_env().images.get(image).id
    except Exception:  # noqa: BLE001
        return None


# ── Kubernetes ────────────────────────────────────────────────────────────────

def _load_k8s(kubeconfig: str):
    from kubernetes import client as k8s_client, config as k8s_config

    k8s_config.load_kube_config(config_file=kubeconfig)
    return k8s_client.CoreV1Api()


def get_k8s_images(kubeconfig: str, namespace: Optional[str] = None) -> dict[str, list[str]]:
    """Returns { "namespace": ["image1", "image2"] }. Requires the kubernetes package and a kubeconfig."""
    try:
        v1 = _load_k8s(kubeconfig)
        pods = v1.list_namespaced_pod(namespace) if namespace else v1.list_pod_for_all_namespaces()

        ns_images: dict[str, list[str]] = {}
        for pod in pods.items:
            ns = pod.metadata.namespace
            ns_images.setdefault(ns, [])
            for c in list(pod.spec.containers or []) + list(pod.spec.init_containers or []):
                if c.image and c.image not in ns_images[ns]:
                    ns_images[ns].append(c.image)
        return ns_images
    except ImportError:
        logger.error("kubernetes package not installed — k8s scanning unavailable")
        return {}
    except Exception as e:  # noqa: BLE001
        logger.error(f"K8s API error: {e}")
        return {}


def flatten_k8s_images(ns_images: dict[str, list[str]]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for images in ns_images.values():
        for img in images:
            if img not in seen:
                seen.add(img)
                result.append(img)
    return result


def get_k8s_inventory(kubeconfig: str, namespace: Optional[str] = None) -> dict[str, Optional[str]]:
    """{image: digest or None}. The digest comes from the pod status, so no registry call is needed."""
    v1 = _load_k8s(kubeconfig)
    pods = v1.list_namespaced_pod(namespace) if namespace else v1.list_pod_for_all_namespaces()
    inventory: dict[str, Optional[str]] = {}
    for pod in pods.items:
        statuses = {}
        for cs in list(pod.status.container_statuses or []) + list(pod.status.init_container_statuses or []):
            m = _DIGEST_RE.search(cs.image_id or "")
            statuses[cs.name] = m.group(1) if m else None
        for c in list(pod.spec.containers or []) + list(pod.spec.init_containers or []):
            if c.image:
                digest = statuses.get(c.name)
                if inventory.get(c.image) is None:
                    inventory[c.image] = digest
    return inventory


# ── Combined discovery for the scheduler ──────────────────────────────────────

def discover(cfg: Settings) -> dict[str, dict[str, Optional[str]]]:
    """{source: {target: image_id}} for the configured scheduler targets.

    A source whose discovery fails is omitted entirely, so its known targets are left untouched.
    """
    result: dict[str, dict[str, Optional[str]]] = {}
    wanted = set(cfg.scheduler_targets)

    docker_targets: dict[str, Optional[str]] = {}
    if "images" in wanted:
        try:
            docker_targets = get_running_docker_inventory()
            result["docker"] = docker_targets
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Docker discovery failed: {e}")

    if "k8s" in wanted and Path(cfg.kubeconfig).exists():
        try:
            k8s = get_k8s_inventory(cfg.kubeconfig)
            result["k8s"] = {img: dig for img, dig in k8s.items() if img not in docker_targets}
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Kubernetes discovery failed: {e}")

    if "filesystem" in wanted:
        paths = {p: None for p in cfg.scan_sources if Path(p).exists()}
        if paths:
            result["filesystem"] = paths
    return result
