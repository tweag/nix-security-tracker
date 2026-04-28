from django.db import models

from shared.models.nix_evaluation import NixMaintainer


class Package(models.Model):
    name = models.CharField(max_length=126)
    homepage = models.URLField(null=True)
    description = models.TextField(null=True)
    maintainers = models.ManyToManyField(NixMaintainer)


class PackageAttrpath(models.Model):
    pk = models.CompositePrimaryKey("package", "attrpath")
    package = models.ForeignKey(
        Package, on_delete=models.CASCADE, related_name="attrpaths"
    )
    attrpath = models.CharField(max_length=255, unique=True)
