from django.contrib import messages
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .models import *
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.conf import settings
from django.contrib import messages
from django.shortcuts import render, redirect
from django.db import IntegrityError
from django.contrib.auth.models import User
from .models import Usuario, TipoUsuario
from django.http import JsonResponse
from flask import Flask, request, jsonify, render_template
import pandas as pd
import pickle
import os
import json
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404, redirect
from django.db.models.deletion import RestrictedError
from django.db.models import ProtectedError

# Create your views here.
def index(request):
    if request.user.is_authenticated:
        context = {
            'user': request.user,
            'usuario': Usuario.objects.get(user=request.user),
            'breeds': RazaGanado.objects.all(),
            'types': TipoGanado.objects.all(),  # Agregar tipos de ganado
            'fincas': Finca.objects.all()  # Agregar fincas del usuario
        }
    else:
        context = {'user': request.user}
    return render(request, 'main/index.html', context)
    

def our_login(request):
    if request.user.is_authenticated:
        # Si ya inició sesión, redirigir al index
        return HttpResponseRedirect('/')
    if request.method == "POST":
        email_f=request.POST['correo']
        password=(request.POST['contra'])
        rememberme = request.POST.get('inputRememberme', "off")
        print(rememberme)
        user = authenticate(username=email_f, password=password)
        if user is not None:
            login(request, user)
            if rememberme == "off":
                request.session.set_expiry(0)
            return HttpResponseRedirect('/')
        else:
            messages.add_message(request, level=messages.WARNING,message='Nombre de usuario o Contraseña Incorrectos')
    return render(request,'main/login.html')


def our_logout(request):
    logout(request)
    return HttpResponseRedirect('/')

def signup(request):
    if request.user.is_authenticated:
        # Si ya ha iniciado sesión, redirigir al índice
        return redirect('/')
    
    if request.method == "POST":
        username = request.POST['inputEmail']
        first_name = request.POST['inputFirstName']
        last_name = request.POST['inputLastName']
        email = request.POST['inputEmail']
        password = request.POST['inputPassword']
        address = request.POST.get('inputAddress', '')
        phone = request.POST.get('inputPhone', '')
        user_type = request.POST.get('inputType', '1')

        try:
            user = User(username=username,
                        first_name=first_name,
                        last_name=last_name,
                        email=email)
            user.set_password(password)
            user.save()
            
            usuario = Usuario(user=user,
                              tipo=TipoUsuario.objects.get(pk=int(user_type)),
                              direccion=address,
                              telefono=phone)
            usuario.save()

            # Autenticar al usuario
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Registro exitoso. ¡Bienvenido!')
                return redirect('/')
            else:
                messages.error(request, 'Autenticación fallida. Por favor, inténtelo de nuevo.')
        except IntegrityError:
            messages.error(request, 'El correo electrónico ya está registrado.')
        except Exception as e:
            messages.error(request, f'Error inesperado: {e}')
    return render(request, 'main/signup.html')

def new_cattle(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return HttpResponseRedirect('/')

    if request.method == "POST":
        vaquita = CabezaGanado(
            customer_name=request.POST['inputCustomerName'],
            peso_kg=float(request.POST['inputWeight']),
            fecha_nacimiento=request.POST['inputBirthdate'],
            tipo=TipoGanado.objects.get(pk=int(request.POST['inputType'])),
            raza=RazaGanado.objects.get(pk=int(request.POST['inputBreed'])),
        )
        vaquita.save()
        associated_estate = GanadoFinca(
        cabeza_ganado=vaquita,
        finca=Finca.objects.get(pk=int(request.POST['inputEstate'])),
        lote=int(request.POST['inputLot']),
        potrero=Potrero.objects.get(pk=int(request.POST['inputPaddock'])),
        )
        associated_estate.save()
        messages.success(request, 'La vaca se ha creado exitosamente.')
        return redirect('my_estates')

    breeds = RazaGanado.objects.all()
    cow_types = TipoGanado.objects.all()
    potreros=Potrero.objects.all()
    estates = Finca.objects.all().filter(usuario=Usuario.objects.get(user=request.user))
    context = {'breeds': breeds, 'cow_types': cow_types, 'potreros': potreros,'estates': estates, 'usuario':Usuario.objects.get(user=request.user)}
    return render(request, 'main/new_cattle.html', context)

def new_estate(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        # Si no inició sesión o inició como un no-ganadero, redirigir al index
        return HttpResponseRedirect('/')
    estates = Finca.objects.all().filter(usuario=Usuario.objects.get(user=request.user))
    breeds = RazaGanado.objects.all()  # Ajusta esto según tu modelo real
    cow_types = TipoGanado.objects.all()  # Ajusta esto según tu modelo real
    context = {
        'estates': estates,
        'user': request.user,
        'usuario': Usuario.objects.get(user=request.user),
        'breeds': breeds,
        'cow_types': cow_types
    }
    if request.method == "POST":
        print(request.POST)
        finca = Finca(usuario=Usuario.objects.get(user=request.user),
                      nombre_finca=request.POST["inputEstateName"],
                      direccion=request.POST["inputAddress"],
                      telefono=request.POST["inputPhone"],
                      direccion_encargado=request.POST["inputStewardAddress"]
                      )
        finca.save()
        return redirect('my_estates')
        estates = Finca.objects.all().filter(usuario=Usuario.objects.get(user=request.user))
        breeds = RazaGanado.objects.all()  # Ajusta esto según tu modelo real
        cow_types = TipoGanado.objects.all()  # Ajusta esto según tu modelo real
        
        context = {
            'estates': estates,
            'user': request.user,
            'usuario': Usuario.objects.get(user=request.user),
            'breeds': breeds,
            'cow_types': cow_types
        }
        return render(request, 'main/my_estates.html', context)
    return render(request, 'main/new_estate.html', context)


def view_estate(request, estate_id):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        # Si no inició sesión o inició como un no-ganadero, redirigir al index
        return HttpResponseRedirect('/')
    finca = Finca.objects.get(usuario=Usuario.objects.get(user=request.user), pk=estate_id)
    vaquitas = GanadoFinca.objects.all().filter(finca=estate_id)
    context = {"finca": finca, "vaquitas": vaquitas, 'user':request.user, 'usuario':Usuario.objects.get(user=request.user)}
    return render(request, 'main/view_estate.html', context)


def cattle_info(request, cattle_id=5):
    lista_contexto = []
    cabeza_de_ganado = CabezaGanado.objects.get(id=cattle_id)
    owner = GanadoFinca.objects.get(cabeza_ganado=cabeza_de_ganado).finca.usuario
    context = {
        "datos_vaca" : cabeza_de_ganado,
        "nombre_raza" : cabeza_de_ganado.raza.nombre_raza,
        "tipo_ganado" : cabeza_de_ganado.tipo.nombre_tipo,
        "owner": owner,
        "owner_fullname": owner.user.get_full_name(),
        'user':request.user,
        'usuario':Usuario.objects.get(user=request.user)
    }
    return render(request, "main/cattle_info.html", context)

def my_estates(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return HttpResponseRedirect('/')
    
    usuario = Usuario.objects.get(user=request.user)
    estates = Finca.objects.filter(usuario=usuario)
    
    cattle_by_estate = {}
    for estate in estates:
        cattle = GanadoFinca.objects.filter(finca=estate)
        cattle_by_estate[estate] = cattle
    
    breeds = RazaGanado.objects.all()
    cow_types = TipoGanado.objects.all()
    
    context = {
        'estates': estates,
        'user': request.user,
        'usuario': usuario,
        'breeds': breeds,
        'cow_types': cow_types,
        'cattle_by_estate': cattle_by_estate,
    }
    return render(request, 'main/my_estates.html', context)


def buscar_vacas(request):
    razas = request.POST.get('raza')
    tipos = request.POST.get('tipo')
    fincas = request.POST.get('finca')
    peso_min = request.POST.get('peso_min')
    peso_max = request.POST.get('peso_max')

    filtros = {}
    if razas:
        filtros['raza__id'] = razas
    if tipos:
        filtros['tipo__id'] = tipos
    if fincas:
        filtros['ganadofinca__finca__id'] = fincas
    if peso_min:
        filtros['peso_kg__gte'] = peso_min
    if peso_max:
        filtros['peso_kg__lte'] = peso_max

    ganado = CabezaGanado.objects.filter(**filtros).distinct()

    context = {
        "vacas": ganado,
        'user': request.user, 
        'usuario': Usuario.objects.get(user=request.user)
    }
    return render(request, "main/busqueda.html", context)


def actualizar(request):
    if request.method == "POST":
        if request.user.is_authenticated:
            request.user.first_name=request.POST['inputFirstName']
            request.user.last_name=request.POST['inputLastName']
            request.user.save()
            usuario=Usuario.objects.get(user=request.user)
            usuario.direccion=request.POST['inputAddress']
            usuario.tipo=TipoUsuario.objects.get(pk=int(request.POST['inputType']))
            usuario.telefono=request.POST['inputPhone']
            usuario.save()
            return HttpResponseRedirect('/') ## Aquí va el url del index según urls.py, 
    context = {'user':request.user,'usuario':Usuario.objects.get(user=request.user)}    
    return render(request, 'main/actualizar.html',context)


def update_cattle(request, cattle_id):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        # Si no inició sesión o inició como un no-ganadero, redirigir al index
        return HttpResponseRedirect('/')
    
    # Obtiene la información de la vaca y la finca asociada
    vaquita = CabezaGanado.objects.get(pk=cattle_id)
    breeds = RazaGanado.objects.all()
    cow_types = TipoGanado.objects.all()
    estates = Finca.objects.all().filter(usuario=Usuario.objects.get(user=request.user))
    associated_estate = GanadoFinca.objects.get(cabeza_ganado=vaquita)
    
    # Obtén los potreros asociados a la finca actual
    potreros = Potrero.objects.filter(finca=associated_estate.finca)
    
    if request.method == "POST":
        # Actualiza los datos de la vaca
        vaquita.customer_name = request.POST['inputCustomerName']
        vaquita.peso_kg = float(request.POST['inputWeight'])
        vaquita.fecha_nacimiento = request.POST['inputBirthdate']
        vaquita.tipo = TipoGanado.objects.get(pk=int(request.POST['inputType']))
        vaquita.raza = RazaGanado.objects.get(pk=int(request.POST['inputBreed']))
        
        # Actualiza la finca y el potrero asociado
        associated_estate.delete()  # Elimina la relación anterior
        associated_estate = GanadoFinca(
            cabeza_ganado=vaquita,
            finca=Finca.objects.get(pk=int(request.POST['inputEstate'])),
            lote=int(request.POST['inputLot']),
            potrero=Potrero.objects.get(pk=int(request.POST['inputPaddock']))  # Ahora usando el potrero seleccionado
        )
        
        # Guarda los cambios
        vaquita.save()
        associated_estate.save()
        
        return HttpResponseRedirect('/cattle_info/%s' % cattle_id)

    context = {
        "vaquita": vaquita, 
        'breeds': breeds, 
        'cow_types': cow_types, 
        'estates': estates, 
        'birthdate': str(vaquita.fecha_nacimiento),
        'associated_estate': associated_estate,
        'potreros': potreros  # Pasamos los potreros al contexto
    }
    
    return render(request, 'main/update_cattle.html', context)

def update_estate(request, estate_id):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        # Si no inició sesión o inició como un no-ganadero, redirigir al index
        return HttpResponseRedirect('/')
    estate = Finca.objects.get(pk=estate_id)
    if request.method == "POST":
        print(request.POST)
        estate.nombre_finca=request.POST["inputEstateName"]
        estate.direccion=request.POST["inputAddress"]
        estate.telefono=request.POST["inputPhone"]
        estate.direccion_encargado=request.POST["inputStewardAddress"]
        estate.save()
        return HttpResponseRedirect('/view_estate/%s' % estate_id)
    context = {"estate": estate}
    return render(request, 'main/update_estate.html', context)


def password_reset(request):
    if request.method == "POST":
        email = request.POST["inputEmail"]
        associated_users = User.objects.filter(username=email)
        if associated_users.exists():
            user = associated_users[0]
            subject = 'Recuperar contraseña'
            email_template_name = "main/password_reset_email.txt"
            c = {
                "email": email,
                "domain": settings.ALLOWED_HOSTS[0],
                "site_name": "BoviApp",
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "token": default_token_generator.make_token(user),
                "protocol": "http"
            }
            email_to_send = render_to_string(email_template_name, c)
            send_mail(subject, email_to_send, settings.EMAIL_HOST_USER, [email], fail_silently=False)
        return HttpResponseRedirect('/')
    context = {"temp": 1}
    return render(request, 'main/password_reset.html', context)


def password_reset_confirm(request, uidb64, token):
    context = {"uid": uidb64, "token": token}
    if request.method == "POST":
        user_pk = int(force_str(urlsafe_base64_decode(uidb64)))
        user = User.objects.get(pk=user_pk)
        user.set_password(request.POST['inputPassword'])
        user.save()
        return HttpResponseRedirect('/')
    return render(request, 'main/password_reset_confirm.html', context)

def new_breed(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return HttpResponseRedirect('/')
    
    if request.method == "POST":
        if 'inputBreedName' in request.POST:  # Para agregar una nueva raza
            breed_name = request.POST.get('inputBreedName', '').strip()
            if breed_name:
                raza = RazaGanado(nombre_raza=breed_name)
                raza.save()
                messages.success(request, 'La raza se ha creado exitosamente.')
                return HttpResponseRedirect('/new_breed')
            else:
                messages.warning(request, 'El nombre de la raza no puede estar vacío.')
        
        elif 'delete_breed' in request.POST:  # Para eliminar una raza
            breed_id = request.POST.get('delete_breed')
            try:
                raza = RazaGanado.objects.get(pk=breed_id)
                raza.delete()
                messages.success(request, 'La raza ha sido eliminada exitosamente.')
            except RestrictedError:
                messages.error(request, 'No se puede eliminar esta raza porque está en uso.')
            return HttpResponseRedirect('/new_breed')
    
    # Obtener todas las razas para listarlas en la tabla
    breeds = RazaGanado.objects.all()
    context = {
        'usuario': Usuario.objects.get(user=request.user),
        'breeds': breeds,
    }
    
    return render(request, 'main/new_funcion.html', context)

def buscarganado(request):
    # Verifica si el usuario tiene el tipo adecuado
    try:
        if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        # Si no inició sesión o inició como un no-ganadero, redirigir al index
            return HttpResponseRedirect('/')
        usuario = Usuario.objects.get(user=request.user)
        if usuario.tipo != TipoUsuario.objects.get(pk=1):
            return redirect('/')  # Redirige si el usuario no es del tipo adecuado
    except Usuario.DoesNotExist:
        return redirect('/')  # Redirige si no se encuentra el usuario
    
    # Renderiza la página de búsqueda
    return render(request, 'main/buscarganado.html')

# Cargar el modelo una vez al inicio del servidor

model = pickle.load(open("model.pkl","rb"))
@csrf_exempt
def predict(request):
    if request.method == "POST":
        if request.content_type == 'application/json':
            try:
                # Cargar los datos JSON desde el cuerpo de la solicitud
                json_data = json.loads(request.body)
               
                # Imprimir los datos recibidos para depuración
                print("Datos JSON recibidos:", json_data)
               
                # Convertir los datos JSON en un DataFrame
                data = pd.DataFrame([json_data])
                vaca_id = json_data.get('vaca')

                # Imprimir las columnas del DataFrame para depuración
                print("Columnas del DataFrame:", data.columns)
               
                # Verificar que los nombres de las columnas coincidan
                required_columns = [
                    'DIM( Days In Milk)', 'Avg(7 days). Daily MY( L )',
                    'Kg. milk 305 ( Kg )', 'Fat (%)', 'SNF (%)',
                    'Density ( Kg/ m3', 'Protein (%)', 'Conductivity (mS/cm)',
                    'pH', 'Freezing point (⁰C)', 'Salt (%)', 'Lactose (%)'
                ]
                # Revisar si las columnas requeridas están presentes en el DataFrame
                missing_columns = [col for col in required_columns if col not in data.columns]
                if missing_columns:
                    return JsonResponse({"error": f"Faltan columnas en los datos: {', '.join(missing_columns)}"}, status=400)
                print(required_columns)
                query_df = data[required_columns]
                prediction = model.predict(query_df)
                if vaca_id:
                    vaca_id = vaca_id.replace('0    ', '')
                    vaca_id = vaca_id.strip()
                    try:
                        vaca = CabezaGanado.objects.get(id=vaca_id)
                        vaca.mastitis = 'y' if prediction[0] == 1 else 'n'
                        vaca.save()
                    except CabezaGanado.DoesNotExist:
                        return JsonResponse({'error': 'Vaca no encontrada'}, status=404)
                    return JsonResponse({"Prediction": list(prediction.astype(str))}, status=200)
            except Exception as e:
                return JsonResponse({"error": str(e)}, status=400)
        else:
            return JsonResponse({"error": "Request is not in JSON format"}, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=405)

def predict_csv(request):
    if request.method == "POST":
        if 'csv_file' not in request.FILES:
            return JsonResponse({"error": "No file part"}, status=400)

        file = request.FILES['csv_file']

        if file.name == '':
            return JsonResponse({"error": "No selected file"}, status=400)
        
        try:
            data = pd.read_excel(file)
            query_df = data[['DIM( Days In Milk)','Avg(7 days). Daily MY( L )', 'Kg. milk 305 ( Kg )', 'Fat (%)' , 'SNF (%)', 'Density ( Kg/ m3','Protein (%)','Conductivity (mS/cm)','pH','Freezing point (⁰C)','Salt (%)','Lactose (%)']]
            index_df = data['Sample No']
            prediction = model.predict(query_df)
            return JsonResponse({"Sample No": list(index_df.astype(str)), "Prediction": list(prediction.astype(str))}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

def prediction_view(request):
    # Obtén el usuario autenticado
    usuario = request.user

    # Obtén el objeto Usuario relacionado con el usuario autenticado
    try:
        usuario_info = Usuario.objects.get(user=usuario)
    except Usuario.DoesNotExist:
        usuario_info = None

    if usuario_info:
        # Obtén las fincas asociadas al usuario
        fincas = Finca.objects.filter(usuario=usuario_info)

        # Obtén todas las vacas asociadas a las fincas del usuario
        vacas = CabezaGanado.objects.filter(ganadofinca__finca__in=fincas).distinct()
    else:
        vacas = CabezaGanado.objects.none()  # Si no hay usuario asociado, no mostrar vacas

    context = {
        'user': usuario,
        'usuario': Usuario.objects.get(user=request.user),
        'vacas': vacas,
    }
    return render(request, "main/predict.html", context)

def cattle_info_by_user(request, username):
    usuario = Usuario.objects.get(user__username=username)
    fincas = usuario.finca_set.all()
    lista_contexto = []
    for finca in fincas:
        ganado_finca = GanadoFinca.objects.filter(finca=finca)
        for gf in ganado_finca:
            cabeza_de_ganado = gf.cabeza_ganado
            context = {
                "datos_vaca": cabeza_de_ganado,
                "nombre_raza": cabeza_de_ganado.raza.nombre_raza,
                "tipo_ganado": cabeza_de_ganado.tipo.nombre_tipo,
                "owner": usuario,
                "owner_fullname": usuario.user.get_full_name(),
                'user': request.user,
                'usuario': usuario
            }
            lista_contexto.append(context)
    return render(request, "main/cattle_info.html", {"cattle_list": lista_contexto})

def delete_cattle(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return HttpResponseRedirect('/')

    if request.method == "POST":
        cattle_id = request.POST.get('cattle_id')
        if cattle_id:
            vaquita = get_object_or_404(CabezaGanado, pk=cattle_id)
            vaquita.delete()
            messages.success(request, 'La vaca ha sido eliminada con éxito.')
            return redirect('my_estates')  # Cambia 'my_estates' por el nombre correcto de tu vista
        
def delete_estate(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        # Si no inició sesión o inició como un no-ganadero, redirigir al index
        return HttpResponseRedirect('/')
    
    finca_id = request.POST.get('finca_id')
    finca = get_object_or_404(Finca, pk=finca_id)
    
    # Eliminar la finca
    finca.delete()
    
    # Agregar un mensaje de éxito
    messages.success(request, "Finca eliminada exitosamente.")
    
    # Redirigir a la página de listado de fincas
    return redirect('my_estates')

def new_potreros(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return HttpResponseRedirect('/')

    if request.method == "POST":
        if 'inputPaddockName' in request.POST:  # Para agregar un nuevo potrero
            nombre_potrero = request.POST.get('inputPaddockName', '').strip()
            finca_id = request.POST.get('inputEstate', '')

            if nombre_potrero and finca_id:
                finca = Finca.objects.get(pk=finca_id)
                potrero = Potrero(nombre_potrero=nombre_potrero, finca=finca)
                potrero.save()
                messages.success(request, 'El potrero se ha creado exitosamente.')
                return HttpResponseRedirect('/new_potreros')
            else:
                messages.warning(request, 'Todos los campos son obligatorios.')

        elif 'delete_paddock' in request.POST:  # Para eliminar un potrero
            potrero_id = request.POST.get('delete_paddock')
            try:
                potrero = Potrero.objects.get(pk=potrero_id)
                # Verificar si el potrero está en uso
                if GanadoFinca.objects.filter(potrero=potrero).exists():
                    messages.error(request, 'No se puede eliminar este potrero porque está en uso.')
                else:
                    potrero.delete()
                    messages.success(request, 'El potrero ha sido eliminado exitosamente.')
            except Potrero.DoesNotExist:
                messages.error(request, 'El potrero no existe.')
            except ProtectedError:
                messages.error(request, 'No se puede eliminar este potrero porque está protegido.')

            return HttpResponseRedirect('/new_potreros')
    
    estates = Finca.objects.filter(usuario=Usuario.objects.get(user=request.user))
    potreros = Potrero.objects.all()  # Obtener todos los potreros
    context = {
        'estates': estates,
        'usuario': Usuario.objects.get(user=request.user),
        'potreros': potreros
    }
    return render(request, 'main/new_potrero.html', context)

def get_potreros(request, finca_id):
    potreros = Potrero.objects.filter(finca_id=finca_id).values('id', 'nombre_potrero')
    return JsonResponse(list(potreros), safe=False)

def get_potreros_by_finca(request):
    finca_id = request.GET.get('finca_id')  # Obtén el id de la finca desde el parámetro GET
    potreros = Potrero.objects.filter(finca_id=finca_id).values('id', 'nombre_potrero')
    return JsonResponse(list(potreros), safe=False)

def get_potreros_update(request, finca_id):
    potreros = Potrero.objects.filter(finca_id=finca_id).values('id', 'nombre_potrero')
    return JsonResponse({'potreros': list(potreros)})

def cattle_by_estate(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return HttpResponseRedirect('/')
    
    estates = Finca.objects.all()
    cattle_by_estate = {}

    if request.method == "POST":
        estate_id = request.POST.get('estate_id')
        if estate_id:
            estate = Finca.objects.get(pk=estate_id)
            # Filtrar ganado usando el modelo GanadoFinca
            ganado_finca = GanadoFinca.objects.filter(finca=estate)
            cattle_by_estate[estate] = ganado_finca

    context = {
        'estates': estates,
        'usuario': Usuario.objects.get(user=request.user),
        'cattle_by_estate': cattle_by_estate
    }
    return render(request, 'main/view_ganado.html', context)

def registrar_vacuna(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return HttpResponseRedirect('/')

    if request.method == "POST":
        vacuna_id = request.POST.get('vacuna')
        cattle_id = request.POST.get('cattle')
        finca_id = request.POST.get('finca')
        fecha_vacuna = request.POST.get('fechaVacuna')

        if vacuna_id and cattle_id and finca_id and fecha_vacuna:
            vacuna = Vacuna.objects.get(pk=vacuna_id)
            cabeza_ganado = CabezaGanado.objects.get(pk=cattle_id)
            finca = Finca.objects.get(pk=finca_id)
            
            registro_vacunacion = RegistroVacunacion(
                vacuna=vacuna,
                cabeza_ganado=cabeza_ganado,
                finca=finca,
                fecha=fecha_vacuna,
                potrero=GanadoFinca.objects.get(pk=cattle_id).potrero
            )
            registro_vacunacion.save()
            
            messages.success(request, 'La vacunación se ha registrado exitosamente.')
            return HttpResponseRedirect('/registrar_vacuna')
        else:
            messages.warning(request, 'Todos los campos son obligatorios.')

    fincas = Finca.objects.filter(usuario=Usuario.objects.get(user=request.user))
    vacunas = Vacuna.objects.all()
    registros_vacunacion = RegistroVacunacion.objects.all()  # Obtener todos los registros de vacunación

    context = {
        'fincas': fincas,
        'vacunas': vacunas,
        'registros_vacunacion': registros_vacunacion,  # Pasar registros al contexto
        'usuario': Usuario.objects.get(user=request.user),
    }

    return render(request, 'main/registrar_vacuna.html', context)

def filtrar_ganado(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return HttpResponseRedirect('/')
    
    # Cargar todas las fincas
    estates = Finca.objects.all()

    if request.method == "POST":
        estate_id = request.POST.get('estate_id')
        if estate_id:
            estate = Finca.objects.get(pk=estate_id)
            # Filtrar ganado asociado a la finca seleccionada
            ganado_finca = GanadoFinca.objects.filter(finca=estate).select_related('cabeza_ganado', 'potrero')

            # Construir la respuesta en formato JSON
            cattle_list = [
                {
                    'id': ganado.cabeza_ganado.id,
                    'nombre': ganado.cabeza_ganado.customer_name,
                    'potrero': ganado.potrero.nombre_potrero
                }
                for ganado in ganado_finca
            ]
            return JsonResponse(cattle_list, safe=False)

    # Contexto inicial para la vista
    context = {
        'estates': estates,
        'usuario': Usuario.objects.get(user=request.user),
    }
    return render(request, 'main/view_ganado.html', context)

def crear_vacuna(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return redirect('/')
    
    if request.method == "POST":
        if 'inputNombreVacuna' in request.POST:  # Para agregar una nueva vacuna
            nombre = request.POST.get('inputNombreVacuna', '').strip()
            descripcion = request.POST.get('inputDescripcionVacuna', '').strip()
            if nombre:
                vacuna = Vacuna(nombre=nombre, descripcion=descripcion)
                vacuna.save()
                messages.success(request, 'Vacuna creada exitosamente.')
                return redirect('registrar_vacuna')
            else:
                messages.warning(request, 'El nombre de la vacuna es obligatorio.')
    
    vacunas = Vacuna.objects.all()
    context = {
        'usuario': Usuario.objects.get(user=request.user),
        'vacunas': vacunas,
    }
    
    return render(request, 'main/registrar_vacuna.html', context)

def mostrar_vacunaciones(request):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return HttpResponseRedirect('/')

    # Obtener todos los registros de vacunación
    registros_vacunacion = RegistroVacunacion.objects.all()

    context = {
        'registros_vacunacion': registros_vacunacion,
        'usuario': Usuario.objects.get(user=request.user),
    }

    return render(request, 'main/mostrar_vacunaciones.html', context)

def eliminar_vacuna(request, vacuna_id):
    if not request.user.is_authenticated or Usuario.objects.get(user=request.user).tipo != TipoUsuario.objects.get(pk=1):
        return redirect('/')

    vacuna = get_object_or_404(Vacuna, pk=vacuna_id)
    
    try:
        vacuna.delete()
        messages.success(request, 'La vacuna ha sido eliminada exitosamente.')
    except ProtectedError:
        messages.error(request, 'No se puede eliminar esta vacuna porque está siendo utilizada en registros de vacunación.')

    return redirect('registrar_vacuna')