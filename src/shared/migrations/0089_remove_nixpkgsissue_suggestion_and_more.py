from django.db import migrations, models
import logging

logger = logging.getLogger(__name__)

def migrate_suggestion_to_suggestions(apps, schema_editor):
    NixpkgsIssue = apps.get_model("shared", "NixpkgsIssue")
    for issue in NixpkgsIssue.objects.exclude(suggestion=None):
        issue.suggestions.add(issue.suggestion)

def migrate_suggestions_to_suggestion(apps, schema_editor):
    NixpkgsIssue = apps.get_model("shared", "NixpkgsIssue")
    for issue in NixpkgsIssue.objects.prefetch_related("suggestions"):
        suggestions = list(issue.suggestions.all())
        if len(suggestions) > 1:
            logger.warning(
                "NixpkgsIssue pk=%s has %d suggestions; only the first will be "
                "kept in the backward migration, the rest will be lost.",
                issue.pk,
                len(suggestions),
            )
        if suggestions:
            issue.suggestion = suggestions[0]
            issue.save()

class Migration(migrations.Migration):

    dependencies = [
        ('shared', '0088_cvederivationclusterproposal_in_issue_draft'),
    ]

    operations = [
        migrations.AddField(
            model_name='nixpkgsissue',
            name='suggestions',
            field=models.ManyToManyField(related_name='nixpkgs_issues', to='shared.cvederivationclusterproposal'),
        ),
        migrations.RunPython(
            migrate_suggestion_to_suggestions,
            reverse_code=migrate_suggestions_to_suggestion,
        ),
        migrations.RemoveField(
            model_name='nixpkgsissue',
            name='suggestion',
        ),
    ]
