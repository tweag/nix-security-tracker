from django.db import models

from shared.models.nix_evaluation import NixDerivation, NixMaintainer


class Package(models.Model):
    name = models.CharField(max_length=126)
    homepage = models.URLField(null=True)
    description = models.TextField(null=True)
    maintainers = models.ManyToManyField(NixMaintainer)


class PackageAttrpath(models.Model):
    """
    Maps a Nixpkgs attribute path to a package.
    The unique index on attrpath enables O(1) lookup during package matching:
    given a derivation's attribute, find its package without scanning derivations.
    """

    pk = models.CompositePrimaryKey("package", "attrpath")
    package = models.ForeignKey(
        Package, on_delete=models.CASCADE, related_name="attrpaths"
    )
    attrpath = models.CharField(max_length=255, unique=True)


class PackageDerivation(models.Model):
    derivation = models.OneToOneField(
        NixDerivation,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="package_link",
    )
    package = models.ForeignKey(
        Package, on_delete=models.CASCADE, related_name="derivations"
    )
