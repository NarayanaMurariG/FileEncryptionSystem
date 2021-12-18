"""PCS_Project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from FileEncryption.views import SignupAPI, LoginAPI, delete_shared_file, get_all_shared_files, get_shared_file, \
    getRecordAPI, UpdateAPI, getPrivateFilesListAPI, delete_files_from_server, index_page, login_page, \
    share_file_with_another_user, signup_page, get_all_public_files, get_public_file, delete_public_file, \
    user_home_page, get_all_users, change_file_permission, error_page, edit_private_file, edit_public_file, \
    getEncryptedRecordAPI, getEncryptedSharedFile

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index_page, name='index_page'),
    path('register/', signup_page, name='sign_up'),
    path('signup/', SignupAPI, name='signup'),
    path('login/', login_page, name='login'),
    path('error/', error_page, name='error'),
    path('authenticate-user/', LoginAPI, name='login'),
    path('user-home/', user_home_page, name='user_home_page'),
    path('get-file/', getRecordAPI, name='get_record'),
    path('update/', UpdateAPI, name='UpdateAPI'),
    path('getprivatefiles/', getPrivateFilesListAPI, name='getPrivateFilesList'),
    path('delete-file/', delete_files_from_server, name='delete-files'),
    path('getpublicfiles/', get_all_public_files, name='get_all_public_files'),
    path('get-public-file/', get_public_file, name='get_public_file'),
    path('delete-public-file/', delete_public_file, name='delete_public_file'),
    path('share-file-with-user/', share_file_with_another_user, name='share_file_with_another_user'),
    path('getsharedfiles/', get_all_shared_files, name='get_all_shared_files'),
    path('get_shared_file/', get_shared_file, name='get_shared_file'),
    path('delete_shared_file/', delete_shared_file, name='delete_shared_file'),
    path('change-file-permission/', change_file_permission, name='change_file_permission'),
    path('getallusers/', get_all_users, name='get_all_users'),
    path('edit-private-file/', edit_private_file, name='edit_private_file'),
    path('edit-public-file/', edit_public_file, name='edit_public_file'),
    path('get-encrypted-file/', getEncryptedRecordAPI, name='getEncryptedRecordAPI'),
    path('get-encrypted-shared-file/', getEncryptedSharedFile, name='getEncryptedSharedFile')
]
