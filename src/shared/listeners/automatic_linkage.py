import pgpubsub

from shared.channels import ContainerChannel
from shared.legacy_matching import legacy_build_new_links
from shared.models.cve import Container


def build_new_links(container: Container) -> bool:
    return legacy_build_new_links(container)


@pgpubsub.post_insert_listener(ContainerChannel)
def build_new_links_following_new_containers(old: Container, new: Container) -> None:
    build_new_links(new)
