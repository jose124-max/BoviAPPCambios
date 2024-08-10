from django.urls import path, include

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('signup', views.signup, name='signup'),
    path('login', views.our_login, name='our_login'),
    path('logout', views.our_logout, name='our_logout'),
    path('password_reset', views.password_reset, name='password_reset'),
    path('password_reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('new_cattle', views.new_cattle, name='new_cattle'),
    path('new_estate', views.new_estate, name='new_estate'),
    path('my_estates', views.my_estates, name='my_estates'),
    path('view_estate/<int:estate_id>', views.view_estate, name='view_estate'),
    path('busqueda', views.buscar_vacas, name='buscar_vacas'),
    path('actualizar', views.actualizar, name='actualizar'),
    path('cattle_info/<int:cattle_id>', views.cattle_info, name='cattle_info'),
    path('update_cattle/<int:cattle_id>', views.update_cattle, name='update_cattle'),
    path('update_estate/<int:estate_id>', views.update_estate, name='update_estate'),
    path('new_breed/', views.new_breed, name='new_breed'),
    path('buscarganado/', views.buscarganado, name='buscar_ganado'),
]
