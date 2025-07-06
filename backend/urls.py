from django.urls import path, include
from .views import *

urlpatterns = [
    path('', index, name='index'),
    # User Management
    path('api/create_user', registerPage, name="register"),
    path('api/send_email_otp/<int:u_id>', resend_otp, name='send_email_otp'),
    path('api/otp_verification', verify_otp, name="otpverification"),
    path('api/login', loginPage, name="login"),
    path('api/googlelogin', googlelogin, name="googlelogin"),
    path('api/logout', logoutUser, name="logout"),
    path('api/users/', get_users),
    path('api/users/<int:u_id>', get_users, name="getuserdetails"),
    path('api/create_tenants', create_tenants),
    path('api/tenants', tenants),
    path('api/tenants/<str:t_id>', tenants),
    path('api/create_organizations', create_organizations),
    path('api/organizations', organizations),
    path('api/organizations/<str:o_id>', organizations),
    path('api/roles', roles,  name='roles'),
    path('api/roles/<str:r_id>', roles,  name='roles'),
    path('api/modify_role/<str:r_id>', modify_role),
    path('api/sessions', UserSessions),
    path('api/sessions/<str:s_id>', UserSessions),
    path('api/send_otp/<str:u_id>', resend_otp),


    path('api/gptresponse/', gpt_response, name='gptresponse'),
    path('api/gpt_graphical/', gpt_graphical, name='gpt_graphical'),
    path('api/file_upload/', uploadFile, name='file_upload'),
    path('api/get_file_name/', user_uploaded_file, name='get_file_name'),
    path('api/dataprocess', data_processing, name='data_process'),
    path('api/get_plots', gen_graphs, name='gen_graphs'),
    path('api/kpi_process', kpi_prompt, name="kpi_process"),
    path('api/mvt', mvt, name='mvt'),
    path('api/generate_code', kpi_code, name="kpi_code"),
    path(r'api/models', models, name='models'),
    path('api/model_predict', model_predict, name='model_predict'),
    path('api/genai_bot', gen_ai_bot, name='gen_ai_bot'),
]
