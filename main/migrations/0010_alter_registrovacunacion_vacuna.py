# Generated by Django 5.0.1 on 2024-08-24 15:51

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0009_alter_registrovacunacion_potrero'),
    ]

    operations = [
        migrations.AlterField(
            model_name='registrovacunacion',
            name='vacuna',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='main.vacuna'),
        ),
    ]
