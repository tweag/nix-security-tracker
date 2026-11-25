import pgpubsub

from shared.channels import ContainerChannel
from shared.models.cve import Container
from shared.pipeline import build_new_links


@pgpubsub.post_insert_listener(ContainerChannel)
def build_new_links_following_new_containers(old: Container, new: Container) -> None:
    build_new_links(new)
