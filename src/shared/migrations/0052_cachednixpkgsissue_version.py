# Generated by Django 4.2.16 on 2025-06-06 09:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('shared', '0051_cachednixpkgsissue_nixpkgsissue_pgpubsub_caec7'),
    ]

    operations = [
        migrations.AddField(
            model_name='cachednixpkgsissue',
            name='version',
            field=models.PositiveIntegerField(default=1),
        ),
    ]
