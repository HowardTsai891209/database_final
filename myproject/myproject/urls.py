from django.contrib import admin
from django.urls import path, include  # 引入 include 來包含其他應用的 urls

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),  # 包含 accounts 應用的 URL 配置
]
