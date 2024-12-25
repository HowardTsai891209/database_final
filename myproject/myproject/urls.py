from django.contrib import admin
from django.urls import path, include  # 引入 include 來包含其他應用的 urls
from accounts.views import login_view, member_view, coach_view, change_password_view, logout_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),  # 包含 accounts 應用的 URL 配置
    path('login/', login_view, name='login'),  # 為 login_view 添加路徑
    path('member/', member_view, name='member'),
    path('coach/', coach_view, name='coach'),
    path('change_password/', change_password_view, name='change_password'),
]
