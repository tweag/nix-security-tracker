from django.db import migrations, models
import django.db.models.deletion


def initialize_suggestion_field(apps, schema_editor):
    """Initialize the suggestion field for existing issues by matching CVE IDs."""
    NixpkgsIssue = apps.get_model('shared', 'NixpkgsIssue')
    CVEDerivationClusterProposal = apps.get_model('shared', 'CVEDerivationClusterProposal')
    
    # Get all issues that don't have a suggestion assigned yet
    issues_without_suggestion = NixpkgsIssue.objects.filter(suggestion__isnull=True)
    
    for issue in issues_without_suggestion:
        # Get the CVE for this issue (assuming one CVE per issue as mentioned)
        issue_cves = issue.cve.all()
        if issue_cves.exists():
            cve = issue_cves.first()
            
            # Find a matching suggestion with the same CVE
            try:
                suggestion = CVEDerivationClusterProposal.objects.get(cve=cve)
                issue.suggestion = suggestion
                issue.save(update_fields=['suggestion'])
            except CVEDerivationClusterProposal.DoesNotExist:
                # If no matching suggestion found, abort the migration
                raise Exception(f"No CVEDerivationClusterProposal found for CVE {cve.id} (issue {issue.id}). Migration aborted.")
            except CVEDerivationClusterProposal.MultipleObjectsReturned:
                # If multiple suggestions exist for the same CVE, take the first one
                suggestion = CVEDerivationClusterProposal.objects.filter(cve=cve).first()
                issue.suggestion = suggestion
                issue.save(update_fields=['suggestion'])


def reverse_initialize_suggestion_field(apps, schema_editor):
    """Reverse migration - clear suggestion field."""
    NixpkgsIssue = apps.get_model('shared', 'NixpkgsIssue')
    NixpkgsIssue.objects.update(suggestion=None)


class Migration(migrations.Migration):

    dependencies = [
        ('shared', '0060_nixpkgsissue_comment'),
    ]

    operations = [
        # First add the field as nullable
        migrations.AddField(
            model_name='nixpkgsissue',
            name='suggestion',
            field=models.OneToOneField(
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.PROTECT, 
                to='shared.cvederivationclusterproposal'
            ),
        ),
        # Then populate the field with data
        migrations.RunPython(
            initialize_suggestion_field,
            reverse_initialize_suggestion_field,
        ),
        # Finally make the field non-nullable
        migrations.AlterField(
            model_name='nixpkgsissue',
            name='suggestion',
            field=models.OneToOneField(
                on_delete=django.db.models.deletion.PROTECT,
                to='shared.cvederivationclusterproposal'
            ),
        ),
    ]
