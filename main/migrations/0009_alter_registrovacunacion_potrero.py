# Generated by Django 5.1 on 2024-08-24 08:29

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0008_vacuna_registrovacunacion'),
    ]

    operations = [
        migrations.AlterField(
            model_name='registrovacunacion',
            name='potrero',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='main.potrero'),
        ),
    ]
