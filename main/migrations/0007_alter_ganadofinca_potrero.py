# Generated by Django 5.1 on 2024-08-22 08:31

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0006_alter_ganadofinca_potrero'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ganadofinca',
            name='potrero',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.potrero'),
        ),
    ]
