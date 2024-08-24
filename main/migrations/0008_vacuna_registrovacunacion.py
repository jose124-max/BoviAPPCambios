# Generated by Django 5.1 on 2024-08-24 08:25

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0007_alter_ganadofinca_potrero'),
    ]

    operations = [
        migrations.CreateModel(
            name='Vacuna',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nombre', models.CharField(max_length=100)),
                ('descripcion', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='RegistroVacunacion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fecha', models.DateField()),
                ('cabeza_ganado', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.cabezaganado')),
                ('finca', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.finca')),
                ('potrero', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.potrero')),
                ('vacuna', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.vacuna')),
            ],
        ),
    ]
