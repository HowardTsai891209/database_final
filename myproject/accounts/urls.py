from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),  # 登入頁面
    path('logout/', views.logout_view, name='logout'),  # 登出頁面
    path('change_password/', views.change_password_view, name='change_password'), # 修改密碼頁面
    path('member/', views.member_view, name='member'),  # 會員頁面
    path('coach/', views.coach_view, name='coach'),  # 教練頁面
]
