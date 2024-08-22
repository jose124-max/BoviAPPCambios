from django.db import models
from django.contrib.auth.models import User



class TipoUsuario(models.Model):
    nombre_tipo = models.CharField(max_length=30)


class Usuario(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    tipo = models.ForeignKey(TipoUsuario, on_delete=models.RESTRICT)
    telefono = models.CharField(max_length=16, default=None, blank=True, null=True)
    direccion = models.CharField(max_length=30, default=None, blank=True, null=True)


class Finca(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    nombre_finca = models.CharField(max_length=50)
    direccion = models.CharField(max_length=50)
    telefono = models.CharField(max_length=16, default=None, blank=True, null=True)
    direccion_encargado = models.CharField(max_length=30, default=None, blank=True, null=True)


class TipoGanado(models.Model):
    nombre_tipo = models.CharField(max_length=30)


class RazaGanado(models.Model):
    nombre_raza = models.CharField(max_length=30)


class CabezaGanado(models.Model):
    TIPO_MASTITIS = [
        ('x', 'No Evaluado'),
        ('y', 'Probable'),
        ('n', 'No Probable'),
    ]

    tipo = models.ForeignKey(TipoGanado, on_delete=models.RESTRICT)
    raza = models.ForeignKey(RazaGanado, on_delete=models.RESTRICT)
    customer_name = models.CharField(max_length=50)
    peso_kg = models.FloatField()
    fecha_nacimiento = models.DateField()
    mastitis = models.CharField(max_length=1, choices=TIPO_MASTITIS, default='x')
    

class Potrero(models.Model):
    nombre_potrero = models.CharField(max_length=50)
    finca = models.ForeignKey(Finca, on_delete=models.CASCADE)

    def __str__(self):
        return self.nombre_potrero

class GanadoFinca(models.Model):
    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['cabeza_ganado', 'finca'], name='pk_compuesta')
        ]

    cabeza_ganado = models.ForeignKey(CabezaGanado, on_delete=models.CASCADE)
    finca = models.ForeignKey(Finca, on_delete=models.CASCADE)
    lote = models.IntegerField()
    potrero = models.ForeignKey(Potrero, on_delete=models.CASCADE)


class Venta(models.Model):
    cabeza_ganado = models.ForeignKey(CabezaGanado, on_delete=models.CASCADE)
    finca = models.ForeignKey(Finca, on_delete=models.CASCADE)
    comprador = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    fecha_venta = models.DateField()
    monto_venta = models.FloatField()
