import base64
import io
import json
import os
import re
import shutil
from collections import defaultdict
from django.core.mail import send_mail
from django.forms.models import model_to_dict
from datetime import datetime
from .models import EmailOTP
import dateutil.parser
from django.utils.dateparse import parse_datetime
import joblib
import tiktoken
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pmdarima as pm
import urllib.parse
from django.contrib.auth import authenticate, login
from django.shortcuts import get_object_or_404
from django.db.models import Prefetch
from django.contrib.auth.decorators import login_required
from django.core.files.storage import default_storage
# For genai using plotly
from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from dotenv import load_dotenv
from keras.models import load_model
from openai import OpenAI
from plotly.graph_objects import Figure
from prophet import Prophet
from sklearn.cluster import KMeans
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.impute import KNNImputer
from sklearn.impute import SimpleImputer
from sklearn.metrics import mean_squared_error
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from statsmodels.tsa.arima.model import ARIMA
from statsmodels.tsa.stattools import adfuller
from wordcloud import WordCloud
from xgboost import XGBRegressor
from .models import Tenant, Organization, UserRole, User, Roles, Sessions
from .database import PostgreSQLDB
from .form import CreateUserForm
from django.utils import timezone
from .aws_s3 import s3_crud
from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings

# Create your views here.


load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MAX_TOKENS = 125000
TOKEN_BUFFER = 3000
SUMMARIZE_THRESHOLD = MAX_TOKENS - 3000
# Configure OpenAI
client = OpenAI(api_key=OPENAI_API_KEY)
os.makedirs('uploads', exist_ok=True)
with open('s3_cred.json', 'r') as fp:
    s3_cred = json.load(fp)

db = PostgreSQLDB(dbname='Aipriori_db', user='test_owner', password='tcWI7unQ6REA')
aws_s3_obj = s3_crud(s3_cred["credentials"]["aws_access_key_id"], s3_cred["credentials"]["aws_secret_access_key"],
                     s3_cred["credentials"]["region_name"])


def index(request):
    return HttpResponse("Hai")


@csrf_exempt
def registerPage(request):
    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            try:
                user = form.save(commit=False)
                user.is_active = False
                user.save()
                if form.cleaned_data.get("organization") or form.cleaned_data.get("roles"):
                    UserRole.objects.create(
                        user=user,
                        organization=form.cleaned_data["organization"],
                        role=form.cleaned_data["roles"]
                    )

                send_otp_email(user)
                return JsonResponse({"message": "User created", "user_id": str(user.id)})
            except Exception as e:
                print(e)
                return JsonResponse({"status": "error", "message": str(e)}, status=500)
        else:
            print(form.errors)
            return JsonResponse({"status": "error", "errors": form.errors}, status=400)


@csrf_exempt
def logoutUser(request):
    pass


@csrf_exempt
def loginPage(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Authenticate the user using the username (retrieved from the email) and password
        user = authenticate(username=email, password=password)

        if user is not None:
            # Log the user in
            login(request, user)
            try:
                user_role = UserRole.objects.get(user_id=user.id)
                organization = Organization.objects.get(id=user_role.organization.id)
                tenant = Tenant.objects.get(id=organization.tenant_id)
            except Exception as e:
                return JsonResponse({"status": "error", "message": f"{e}"}, status=400)
            # Prepare the user details to return as a response
            user_details = {
                'username': user.username,
                'email': user.email,
                'id': user.id,
                'last_login': user.last_login,
                'role': user_role.role,
                'tenant': {
                    'tenant_id': tenant.id,
                    'tenant_name': tenant.name,
                    'tenant_type': tenant.type,
                    'tenant_timeout': tenant.timeout
                },
                'organization': {
                    'organization_id': organization.id,
                    'organization_name': organization.name,
                    'organization_logo': organization.image_data,
                    'organization_logo_name': organization.image_name
                }
            }

            return JsonResponse({"status": "success", "user": user_details})
        else:
            return JsonResponse({"status": "error", "message": "Invalid email or password"}, status=401)

    return JsonResponse({"status": "error", "message": "Login failed"}, status=400)


@csrf_exempt
def googlelogin(request):
    if request.method == 'POST':
        try:
            username = request.POST.get("username")
            user_id = request.POST.get("id")
            email = request.POST.get("email")

            # Generate a password (you might want to handle this differently in production)
            password = "auto@" + user_id

            # Check if the user already exists
            users = db.get_users()
            if email in [user[0] for user in users]:
                user_details = db.get_user_data(email)
                return JsonResponse({"status": "Success", "user_details": user_details})
            else:
                # Create a new user
                form = CreateUserForm({
                    'username': username,
                    'email': email,
                    'password1': password,
                    'password2': password
                })
                if form.is_valid():
                    form.save()
                    db.add_user(
                        user_name=username,
                        password=password,
                        email=email,
                    )
                    user_details = db.get_user_data(email)
                    return JsonResponse({"status": "Success", "user_details": user_details})
                else:
                    return JsonResponse({"status": "Error", "errors": form.errors})
        except Exception as e:
            return JsonResponse({"status": "Error", "message": str(e)})
    else:
        return JsonResponse({"status": "Error", "message": "Invalid request method"})


@csrf_exempt
def create_tenants(request):
    if request.method == 'POST':
        t_name = request.POST.get('tenant_name')
        t_type = request.POST.get('tenant_type')
        t_timeout = request.POST.get('timeout')
        try:
            if Tenant.objects.filter(name=t_name, type=t_type).exists():
                return JsonResponse({
                    'status': 'duplicate',
                    'message': f"Tenant with name '{t_name}' and type '{t_type}' already exists"
                }, status=409)

            tenant = Tenant.objects.create(name=t_name, type=t_type, timeout=t_timeout)
            tenant_details = {
                "Tenant id": tenant.id,
                "Tenant Name": tenant.name,
                "Tenant type": tenant.type,
                "Timeout": tenant.timeout
            }
            return JsonResponse({'status': 'created', 'tenant_details': tenant_details})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)


@csrf_exempt
def tenants(request, t_id=None):
    if request.method == 'GET':
        if t_id:
            try:
                tenant = Tenant.objects.get(id=t_id)
                if tenant:
                    tenant_details = {
                        "Tenant id": tenant.id,
                        "Tenant Name": tenant.name,
                        "Tenant type": tenant.type,
                        "Timeout": tenant.timeout
                    }
                    return JsonResponse({'status': 'Tenant Found', 'Tenant Details': tenant_details})
                else:
                    return JsonResponse({'status': "Tenant not found"})
            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)}, status=400)
        else:
            tenants = Tenant.objects.all().values('id', 'name', 'type', 'timeout')
            return JsonResponse({'tenants': list(tenants)}, safe=False)
    elif request.method == 'POST':
        if not t_id:
            return HttpResponseBadRequest("Tenant ID required for update.")
        t_name = request.POST.get('tenant_name')
        t_type = request.POST.get('tenant_type')
        t_timeout = request.POST.get('tenant_timeout')
        if t_id:
            try:
                tenant = Tenant.objects.get(id=t_id)
                if t_name:
                    tenant.name = t_name

                if t_type:
                    tenant.type = t_type
                if t_timeout:
                    tenant.timeout = t_timeout

                tenant.save()

                return JsonResponse({"status": "records updated successfully",
                                     'Updated Detais': {
                                         "tenant_id": tenant.id,
                                         'tenant_name': tenant.name,
                                         'tenant_type': tenant.type,
                                         'timeout': tenant.timeout
                                     }
                                     }, status=200)

            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)}, status=400)
    elif request.method == 'DELETE':
        try:
            tenant = Tenant.objects.get(id=t_id)
            tenant.delete()
            return JsonResponse({"status": "success", "message": 'Tenant Deleted'}, status=200)
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)


@csrf_exempt
def create_organizations(request):
    if request.method == 'POST':
        try:
            t_id = request.POST.get('tenant_id')
            o_name = request.POST.get('organization_name')
            p_o_id = request.POST.get('parent_organization_id')
            logo = request.FILES.get('logo')

            if p_o_id in [None, 'null', '']:
                p_o_id = None
            if Organization.objects.filter(name=o_name, tenant=t_id).filter(
                    Q(parent=p_o_id) | Q(parent__isnull=True)).exists():
                tenant = Tenant.objects.get(id=t_id)
                parent = Organization.objects.get(id=p_o_id) if p_o_id else None
                org = Organization.objects.get(name=o_name, tenant=tenant, parent=parent)
                organization_details = {
                    "Organization id": org.id,
                    "Organization name": org.name,
                    "Tenant id": org.tenant.id,
                    "Parent id": org.parent,
                    "logo_data": org.image_data,
                    "logo_name": org.image_name
                }
                return JsonResponse({
                    'status': 'duplicate',
                    'message': f'Organization with provided details exists already',
                    'Organizations details': organization_details
                }, status=409)

            tenant = Tenant.objects.get(id=t_id)
            parent = Organization.objects.get(id=p_o_id) if p_o_id else None
            org = Organization.objects.create(name=o_name, tenant=tenant, parent=parent)
            aws_s3_obj.upload_file_obj_to_s3(logo,
                                             s3_cred["credentials"]['base_bucket_name'],
                                             f'Organizations/{org.id}/{logo.name}', 'image')
            logo_name = urllib.parse.quote_plus(logo.name, safe="()")
            org.image_data = f"https://aipriori-backend.s3.eu-west-1.amazonaws.com/Organizations/{org.id}/{logo_name}"
            org.image_name = logo_name
            org.save()
            organization_details = {
                "Organization id": org.id,
                "Organization name": org.name,
                "Tenant id": org.tenant.id,
                "Parent id": org.parent,
                "logo_data": org.image_data,
                "logo_name": org.image_name
            }
            return JsonResponse({'status': 'created', 'organization_details': organization_details})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)


@csrf_exempt
def organizations(request, o_id=None):
    if request.method == 'GET':
        tenant_id = request.GET.get('tenant_id')
        if o_id:
            try:
                org = Organization.objects.get(id=o_id)

                tenannt_obj = Tenant.objects.get(id=org.tenant_id)

                if org:
                    organization_details = {
                        "Organization id": org.id,
                        "Organization name": org.name,
                        "Tenant": {
                            "Tenant Id": tenannt_obj.id,
                            "Tenant Name": tenannt_obj.name,
                            "Tenant Type": tenannt_obj.type,
                            "Tenant Timeout": tenannt_obj.timeout,
                        },
                        "Parent Tenant": str(org.parent.id) if org.parent else None,
                        "logo_data": org.image_data,
                        "logo_name": org.image_name
                    }
                    return JsonResponse({'status': 'Organization Found', 'Organization Details': organization_details})
                else:
                    return JsonResponse({'status': "organization not found"})
            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)}, status=400)
        elif tenant_id:
            try:
                tenant = Tenant.objects.get(id=tenant_id)
            except Tenant.DoesNotExist:
                tenant = None
            if tenant:
                if Organization.objects.filter(tenant=tenant.id).exists():
                    orgs = []
                    for org in Organization.objects.filter(tenant=tenant.id):
                        org_dict = {
                            'id': str(org.id),
                            'name': org.name,
                            'tenant': {
                                "Tenant Id": tenant.id,
                                "Tenant Name": tenant.name,
                                "Tenant Type": tenant.type,
                                "Tenant Timeout": tenant.timeout,
                            },
                            'parent': str(org.parent.id) if org.parent else None,
                            'logo_name': org.image_name,
                            'logo_data': org.image_data
                        }
                        orgs.append(org_dict)
                    return JsonResponse({'organizations': orgs}, safe=False)
            else:
                return JsonResponse({'status': 'Organization not found',
                                     'Message': "No organization found under specified tenant"})
        else:
            orgs = []
            organizations = Organization.objects.select_related('tenant', 'parent').all()

            for org in organizations:
                tenant = org.tenant  # Already fetched with select_related
                org_dict = {
                    'id': str(org.id),
                    'name': org.name,
                    'tenant': {
                        "Tenant Id": tenant.id,
                        "Tenant Name": tenant.name,
                        "Tenant Type": tenant.type,
                        "Tenant Timeout": tenant.timeout,
                    } if tenant else None,
                    'parent': str(org.parent.id) if org.parent else None,
                    'logo_name': org.image_name,
                    'logo_data': org.image_data
                }
                orgs.append(org_dict)

            return JsonResponse({'organizations': orgs}, safe=False)
    elif request.method == 'POST':
        if not o_id:
            return HttpResponseBadRequest("Organization ID required for update.")
        tenant_id = request.POST.get('tenant')
        name = request.POST.get('name')
        parent = request.POST.get('parent')
        logo = request.FILES.get('logo')
        if o_id:
            try:
                organization = Organization.objects.get(id=o_id)
                if tenant_id:
                    try:
                        tenant = Tenant.objects.get(id=tenant_id)
                        organization.tenant = tenant
                    except Organization.DoesNotExist:
                        return JsonResponse({
                            "status": "error",
                            "message": f"Tenant with ID {tenant_id} does not exist."
                        }, status=400)

                if name:
                    organization.name = name

                if parent:
                    try:
                        tenant = Tenant.objects.get(id=parent)
                        organization.parent = tenant
                    except Organization.DoesNotExist:
                        return JsonResponse({
                            "status": "error",
                            "message": f"Tenant with ID {tenant_id} does not exist."
                        }, status=400)
                if logo:
                    try:
                        aws_s3_obj.upload_file_obj_to_s3(logo,
                                                         s3_cred["credentials"]['base_bucket_name'],
                                                         f'Organizations/{organization.id}/{logo.name}', 'image')

                    except Exception as e:
                        return JsonResponse({'message': str(e)}, status=400)
                    logo_name = urllib.parse.quote_plus(logo.name, safe="()")
                    organization.image_data = f"https://aipriori-backend.s3.eu-west-1.amazonaws.com/Organizations/{organization.id}/{logo_name}"
                    organization.image_name = logo_name

                organization.save()

                return JsonResponse({"status": "records updated successfully",
                                     'Updated Detais': {
                                         "organization_id": organization.id,
                                         'organization_name': organization.name,
                                         "tenant": organization.tenant.id,
                                         'parent': organization.parent.id if organization.parent else organization.parent,
                                         "logo_data": organization.image_data,
                                         "logo_name": organization.image_name
                                     }
                                     }, status=200)
            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)}, status=400)

    elif request.method == 'DELETE':
        try:
            organization = Organization.objects.get(id=o_id)
            organization.delete()
            return JsonResponse({"status": "success", "message": 'Organization Deleted'}, status=200)
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)


@csrf_exempt
def assign_user_role(request):
    if request.method == 'POST':
        try:
            user_id = request.POST.get('user_id')
            organization_id = request.POST.get('organization_id')
            role = request.POST.get('role')
            user = User.objects.get(id=user_id)
            org = Organization.objects.get(id=organization_id)
            role_obj = UserRole.objects.create(user=user, organization=org, role=role)
            user_role_details = {"user_id": user_id, "organization_id": organization_id, "role": role,
                                 "role_id": role_obj.id}
            return JsonResponse({'status': 'assigned', 'user_role_details': user_role_details})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)


@csrf_exempt
def roles(request, r_id=None):
    if request.method == 'POST':
        try:
            role = request.POST.get('roles')
            permissions = request.POST.getlist('permissions')
            organization_id = request.POST.get('organization')
            if not role or not permissions:
                return JsonResponse({"error": "Missing role or permissions"}, status=400)
            if not organization_id:
                return JsonResponse({"error": "Missing organization id"}, status=400)
            try:
                organization = Organization.objects.get(id=organization_id)
            except Organization.DoesNotExist:
                return JsonResponse({
                    "status": "error",
                    "message": f"Organization with ID {organization_id} does not exist."
                }, status=400)

            role_obj = Roles.objects.create(role=role, permissions=permissions, organization=organization)
            role_details = {"role_id": role_obj.id, "role": role_obj.role, "permissions": role_obj.permissions,
                            "organization": role_obj.organization.id}
            return JsonResponse({'status': 'role created', 'roledetails': role_details})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)
    elif request.method == "GET":
        o_id = request.GET.get('o_id')
        if o_id:
            try:
                organization = Organization.objects.get(id=o_id)
            except Organization.DoesNotExist:
                return JsonResponse({
                    "status": "error",
                    "message": f"Organization with ID {o_id} does not exist."
                }, status=400)

            try:
                roles_obj = Roles.objects.filter(organization=organization).values('id', 'role', 'permissions',
                                                                                   'organization')
                return JsonResponse({'status': 'success', 'roles': list(roles_obj)})
            except Roles.DoesNotExist:
                return JsonResponse({
                    "status": "error",
                    "message": f"Roles with organization ID {o_id} does not exist."
                }, status=400)

        roles_obj = Roles.objects.all().values('id', 'role', 'permissions', 'organization')
        return JsonResponse({'status': 'success', 'roles': list(roles_obj)})


@csrf_exempt
def modify_role(request, r_id=None):
    if request.method == 'DELETE':
        try:
            role_obj = Roles.objects.get(id=r_id)
            role = list(Roles.objects.values_list('role', flat=True))[0]
            user_roles = UserRole.objects.all().values_list('role', flat=True)
            if role not in user_roles:
                role_obj.delete()
                return JsonResponse({'status': 'success', 'msg': 'Role deleted'})
            else:
                return JsonResponse({'status': 'error', 'msg': f'{role} is allocated to user, '
                                                               f'failed to delete'})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)
    elif request.method == 'POST':
        try:
            permissions = request.POST.getlist('permissions')
            organization_id = request.POST.get('organization_id')
            try:
                role_obj = Roles.objects.get(id=r_id)
            except Roles.DoesNotExist:
                return JsonResponse({
                    "status": "error",
                    "message": f"Roles with ID {r_id} does not exist."
                }, status=400)
            if permissions:
                role_obj.permissions = permissions
            if organization_id:
                try:
                    organization = Organization.objects.get(id=organization_id)
                except Organization.DoesNotExist:
                    return JsonResponse({
                        "status": "error",
                        "message": f"Organization with ID {organization_id} does not exist."
                    }, status=400)
                role_obj.organization = organization
            role_obj.save()
            role_details = {"role_id": role_obj.id, "role": role_obj.role, "permissions": role_obj.permissions,
                            'organization': role_obj.organization.id}
            return JsonResponse({'status': 'success', 'Updated Role': role_details})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)


@csrf_exempt
def UserSessions(request, s_id=None):
    if request.method == 'POST':
        try:
            if s_id:
                try:
                    session_obj = Sessions.objects.get(id=s_id)
                    logoutTime = request.POST.get('logoutTime')
                    status = request.POST.get('status')
                    if logoutTime:
                        logout_dt = parse_datetime(logoutTime)
                        session_obj.logoutTime = logout_dt
                        if session_obj.loginTime and logout_dt:
                            duration = (logout_dt - session_obj.loginTime).total_seconds() / 60.0
                            session_obj.durationMinutes = round(duration, 2)

                    if status:
                        session_obj.status = status
                    session_obj.save()
                    return JsonResponse({'status': 'success', 'session_details': model_to_dict(session_obj)},
                                        status=200)
                except Sessions.DoesNotExist:
                    return JsonResponse({
                        "status": "error",
                        "message": f"Session with ID {s_id} does not exist."
                    }, status=400)

            userId = request.POST.get('userId')
            userName = request.POST.get('userName')
            userEmail = request.POST.get('userEmail')
            orgId = request.POST.get('orgId')
            ipAddress = request.POST.get('ipAddress')
            deviceInfo = request.POST.get('deviceInfo')
            loginTime = request.POST.get('loginTime')

            session_obj = Sessions.objects.create(
                userId=userId,
                userName=userName,
                userEmail=userEmail,
                orgId=orgId,
                ipAddress=ipAddress,
                deviceInfo=deviceInfo,
                loginTime=loginTime,
                status='active'
            )
            session_details = {
                "session_id": session_obj.id,
                "userId": session_obj.userId,
                "userName": session_obj.userName,
                "userEmail": session_obj.userEmail,
                "orgId": session_obj.orgId,
                "ipAddress": session_obj.ipAddress,
                "deviceInfo": session_obj.deviceInfo,
                "loginTime": session_obj.loginTime
            }
            return JsonResponse({'status': 'session created', 'session_details': session_details}, status=201)
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)
    elif request.method == "GET":
        o_id = request.GET.get('orgId')
        userId = request.GET.get('userId')
        startDate = request.GET.get('startDate')
        endDate = request.GET.get('endDate')
        if o_id:
            try:
                organization = Organization.objects.get(id=o_id)
                filters = {
                    'orgId': o_id
                }
            except Organization.DoesNotExist:
                return JsonResponse({
                    "status": "error",
                    "message": f"Organization with ID {o_id} does not exist."
                }, status=400)

            if userId:
                filters['userId'] = userId

            if startDate and endDate:
                endDate = datetime.strptime(endDate, '%Y-%m-%d')
                endDate = endDate.replace(hour=23, minute=59, second=59)
                filters['loginTime__range'] = (startDate, endDate)
            sessions_qs = Sessions.objects.filter(**filters)
            sessions_data = list(sessions_qs.values())

            total = sessions_qs.count()
            active_sessions = sessions_qs.filter(status='active').count()

            return JsonResponse({
                'total': total,
                'activeSessions': active_sessions,
                'sessions': sessions_data
            })

        if s_id:
            try:
                session_obj = Sessions.objects.get(id=s_id)
                session_details = {
                    "session_id": session_obj.id,
                    "userId": session_obj.userId,
                    "userName": session_obj.userName,
                    "userEmail": session_obj.userEmail,
                    "orgId": session_obj.orgId,
                    "ipAddress": session_obj.ipAddress,
                    "deviceInfo": session_obj.deviceInfo,
                    "loginTime": session_obj.loginTime,
                    "logoutTime": session_obj.logoutTime,
                    "durationMinutes": session_obj.durationMinutes,
                    "status": session_obj.status
                }
                return JsonResponse({'status': 'success', 'session_details': session_details}, status=200)
            except Sessions.DoesNotExist:
                return JsonResponse({
                    "status": "error",
                    "message": f"Session with ID {o_id} does not exist."
                }, status=400)

        session_obj = Sessions.objects.all().values('id', "userId", "userName", "userEmail", "orgId", "ipAddress",
                                                    "deviceInfo", "loginTime", "logoutTime", "durationMinutes",
                                                    "status")
        return JsonResponse({'status': 'success', 'sessions': list(session_obj)})


@csrf_exempt
def get_users(request, u_id=None):
    if request.method == 'GET':
        organization_id = request.GET.get('organization_id')
        user_role = request.GET.get('user_role')
        if u_id:
            tenant_details = None
            try:
                # Fetch user
                user = get_object_or_404(User, id=u_id)

                # Try to get user role
                role = UserRole.objects.select_related('organization').filter(user_id=user.id).first()

                organization_details = None
                tenant_details = None

                if role and role.organization:
                    org = role.organization
                    organization_details = {
                        'organization_id': org.id,
                        'organization_name': org.name
                    }

                    # Try to get tenant
                    try:
                        tenant = Tenant.objects.get(id=org.tenant_id)
                        tenant_details = {
                            'tenant_id': tenant.id,
                            'tenant_name': tenant.name,
                            'tenant_type': tenant.type,
                            'tenant_timeout': tenant.timeout
                        }
                    except Tenant.DoesNotExist:
                        pass

                data = {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_active": user.is_active,
                    'role': role.role if role else None,
                    'tenant': tenant_details,
                    'organization': organization_details
                }

                return JsonResponse(data)

            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)}, status=400)
        elif organization_id or user_role:
            organization_id = request.GET.get('organization_id')
            user_role = request.GET.get('user_role')

            user_role = user_role if isinstance(user_role, list) else user_role

            try:
                filters = {}
                if organization_id:
                    filters['organization__id'] = organization_id
                if user_role:
                    filters['role'] = user_role

                user_roles = UserRole.objects.filter(**filters).select_related('user', 'organization')

                user_data = []
                tenant_cache = {}

                for ur in user_roles:
                    org = ur.organization
                    tenant = None

                    if org:
                        if org.tenant_id in tenant_cache:
                            tenant = tenant_cache[org.tenant_id]
                        else:
                            try:
                                tenant = Tenant.objects.get(id=org.tenant_id)
                                tenant_cache[org.tenant_id] = tenant
                            except Tenant.DoesNotExist:
                                tenant = None

                    user_data.append({
                        'id': ur.user.id,
                        'username': ur.user.username,
                        'email': ur.user.email,
                        'role': ur.role,
                        'tenant': {
                            'tenant_id': tenant.id,
                            'tenant_name': tenant.name,
                            'tenant_type': tenant.type,
                            'tenant_timeout': tenant.timeout
                        } if tenant else None,
                        'organization': {
                            'organization_id': org.id,
                            'organization_name': org.name,
                        } if org else None
                    })

                return JsonResponse({'users': user_data}, safe=False)

            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)}, status=400)
        else:
            try:
                user_roles = UserRole.objects.select_related('organization__tenant')
                users = User.objects.prefetch_related(
                    Prefetch('userrole_set', queryset=user_roles, to_attr='user_roles')
                )

                user_data = []
                for user in users:
                    user_role = user.user_roles[0] if user.user_roles else None
                    organization = user_role.organization if user_role else None
                    tenant = organization.tenant if organization else None

                    user_data.append({
                        'username': user.username,
                        'email': user.email,
                        'id': user.id,
                        'last_login': user.last_login,
                        'role': user_role.role if user_role else None,
                        'tenant': {
                            'tenant_id': tenant.id,
                            'tenant_name': tenant.name,
                            'tenant_type': tenant.type,
                            'tenant_timeout': tenant.timeout
                        } if tenant else None,
                        'organization': {
                            'organization_id': organization.id,
                            'organization_name': organization.name,
                        } if organization else None
                    })

                return JsonResponse(user_data, safe=False)

            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)}, status=400)




    elif request.method == 'POST':
        if not u_id:
            return HttpResponseBadRequest("User ID required for update.")
        try:
            user = User.objects.get(id=u_id)
            user_role = UserRole.objects.get(user=user.id)

            username = request.POST.get('username')
            if username:
                user.username = username
            email = request.POST.get('email')
            if email:
                user.email = email

            password = request.POST.get('password')
            if password:
                user.set_password(password)

            status = request.POST.get('status')
            if status:
                user.is_active = (status == 'True')
            user.save()

            organization_id = request.POST.get('organization')
            if organization_id:
                try:
                    organization = Organization.objects.get(id=organization_id)
                    user_role.organization = organization
                except Organization.DoesNotExist:
                    return JsonResponse({
                        "status": "error",
                        "message": f"Organization with ID {organization_id} does not exist."
                    }, status=400)

            user_role_ = request.POST.getlist('user_role')
            if user_role_:
                user_role.role = user_role_

            user_role.save()

            updated_user_details = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_active": user.is_active,
                'organization': user_role.organization.id,
                'role': user_role.role
            }

            return JsonResponse({"status": "success", "Updated user details": updated_user_details})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)
    elif request.method == 'DELETE':
        try:
            user = User.objects.get(id=u_id)
            user_role = UserRole.objects.get(user=user)

            user_role.delete()
            user.delete()
            return JsonResponse({"status": "success", "message": 'User Deleted'}, status=200)
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)


@csrf_exempt
def resend_otp(request, u_id):
    try:
        user = User.objects.get(id=u_id)
        send_otp_email(user)
        return JsonResponse({"status": "success", "message": "OTP sent to the registered mail"}, status=200)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=400)


def send_otp_email(user):
    otp_entry, created = EmailOTP.objects.get_or_create(user=user)
    otp_entry.generate_otp()
    send_mail(
        'Your OTP Code',
        f'Your OTP code is: {otp_entry.otp}',
        'alimisumanth729@gmail.com',
        [user.email],
        fail_silently=False,
    )


@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp_input = request.POST.get('otp')

        try:
            user = User.objects.get(email=email)
            otp_entry = EmailOTP.objects.get(user=user)
            if otp_entry.is_valid(otp_input):
                user.is_active = True
                user.save()
                otp_entry.delete()
                return JsonResponse({
                    "status": "success",
                    "message": "OTP verified"
                }, status=200)
            else:
                return JsonResponse({
                    "status": "error",
                    "message": "Invalid OTP or OTP expired."
                })
        except User.DoesNotExist:
            return JsonResponse({
                "status": "error",
                "message": "User not found."
            })
        except EmailOTP.DoesNotExist:
            return JsonResponse({
                "status": "error",
                "message": "OTP record not found for the user."
            })
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": str(e)
            })


@csrf_exempt
def gpt_response(request):
    try:
        prompt = request.POST.get('prompt')
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        processed_data = process_response(response)
        return HttpResponse(json.dumps({'result': processed_data}), content_type="application/json")
    except Exception as e:
        print(e)
        return str(e)


def process_response(response_data):
    processed_data = ""
    # Display generated content dynamically
    for choice in response_data.choices:
        message = choice.message
        chunk_message = message.content if message else ''
        processed_data += chunk_message
    processed_data = processed_data.replace('```python', '').replace('```', '')
    return processed_data


@csrf_exempt
def uploadFile(request):
    """
    This method is used for uploading files
    @args: None
    returns: None
    """
    try:
        if request.method == 'POST':
            file = request.FILES.get('file')
            file_status = request.POST.get('file_status')
            user_id = request.headers.get('X-User-ID')
            if not file:
                return HttpResponse('No files uploaded')
            file_name, file_extension = os.path.splitext(os.path.basename(file.name))
            if file_name in aws_s3_obj.list_s3_files(s3_cred["credentials"]['base_bucket_name'],
                                                     f"{user_id}/")["files"] and file_status not in ['replace',
                                                                                                    'rename']:
                return JsonResponse({"message": "Please select the file upload status to continue"})

            if file_status:
                if file_status.lower() == 'replace':
                    aws_s3_obj.delete_s3_folder(s3_cred["credentials"]['base_bucket_name'],
                                                f'{user_id}/{file_name}')
                elif file_status.lower() == 'rename':
                    existing_files = aws_s3_obj.list_s3_files(s3_cred["credentials"]['base_bucket_name'],
                                             f"{user_id}/")["files"]
                    match = re.match(r"^(.*)_V_\d+$", file_name)
                    base_name = match.group(1) if match else file_name
                    file_name = base_name[:]
                    count = 1
                    while file_name in existing_files:
                        file_name = base_name + f"_V_{count}"
                        count+=1

            file.seek(0)
            try:
                # Directly upload Django UploadedFile object to S3
                aws_s3_obj.upload_file_obj_to_s3(file, s3_cred["credentials"]['base_bucket_name'],
                                                 f'{user_id}/{file_name}/input_files/{file_name}{file_extension}')

                aws_s3_obj.upload_file_obj_to_s3({'file_name': file_name},
                                                 s3_cred["credentials"]['base_bucket_name'],
                                                 f'{user_id}/file_properties.json', 'json')
            except (BotoCoreError, ClientError) as e:
                print(f'Failed to upload: {str(e)}')

            user_id = request.headers.get('X-User-id')
            # df = pd.read_csv(io.BytesIO(file_content))
            # session = ChatSession.objects.create(user_id=user_id)
            # session.csv_file = file.name
            # session.base_context = summarize_csv(df)
            # session.csv_columns = list(df.columns)
            # session.csv_stats = df.describe(include='all').replace({np.nan: None}).to_dict()
            # session.session_name = f"Uploaded: {file.name}"
            # session.save()

            return HttpResponse(json.dumps({'status': "Success", 'file_name': file_name+file_extension}),
                                content_type="application/json")
    except Exception as e:
        return HttpResponse(str(e))


@csrf_exempt
def check_input_file(request):
    file_name = request.POST.get('file_name')
    user_id = request.headers.get('X-User-ID')
    file_status = aws_s3_obj.check_s3_file(s3_cred["credentials"]['base_bucket_name'],
                                           f'{user_id}/{file_name.split(".")[0]}/input_files/{file_name}')
    if file_status['status']:
        return JsonResponse({"message": "File exists", "status": True})
    else:
        return JsonResponse({"message": f"File doest not exists: {file_status['message']}", "status": False})


@csrf_exempt
def get_s3_files(request):
    user_id = request.headers.get('X-User-ID')
    result = aws_s3_obj.list_s3_files(s3_cred["credentials"]['base_bucket_name'], f"{user_id}/")
    if result["status_code"] == 200:
        return JsonResponse({"message": "FilesRetrieved", "available_files": result['files'], "status": True})
    else:
        return JsonResponse({"message": f"Error in retrieving fies: {result['error']}", "status": False})


def process_file(user_id):
    try:
        user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                             f'{user_id}/file_properties.json', 'json')
        df = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                      f'{user_id}/{user_file["file_name"]}/input_files/{user_file["file_name"]}.csv', 'csv')

        new_df, html_df, summary = process_missing_data(df.copy())

        aws_s3_obj.upload_file_obj_to_s3(new_df, s3_cred["credentials"]['base_bucket_name'],
                                         f'{user_id}/{user_file["file_name"]}/processed_files/processed_data.csv', 'csv')

        aws_s3_obj.upload_file_obj_to_s3({"data": html_df, "summary": summary},
                                         s3_cred["credentials"]['base_bucket_name'],
                                         f'{user_id}/{user_file["file_name"]}/processed_files/mvt_data.json', 'json')
        return {'message': "File processed", "status": True}
    except Exception as e:
        return {'message': str(e), "status": False}


def check_processed_file(user_id, user_file):
    check_s3_file_obj = aws_s3_obj.check_s3_file(s3_cred["credentials"]['base_bucket_name'],
                                                 f'{user_id}/{user_file["file_name"]}/processed_files/processed_data.csv')
    if not check_s3_file_obj['status']:
        return process_file(user_id)
    return {'message': "File processed", "status": True}


# Ensure JSON serialization by converting NumPy arrays to lists
def make_serializable(obj):
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {k: make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_serializable(v) for v in obj]
    return obj


@csrf_exempt
def user_uploaded_file(request):
    try:
        user_id = request.headers.get('X-User-ID')
        user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                             f'{user_id}/file_properties.json', 'json')
        return JsonResponse({"file_name": user_file.get('file_name')})
    except Exception as e:
        return JsonResponse({"message": str(e)}, status=400)

@csrf_exempt
def update_user_selected_file(request):
    try:
        user_id = request.headers.get('X-User-ID')
        user_selected_file = request.POST.get('file_name')
        if not user_selected_file:
            return JsonResponse({"message":"Please select the fileto continue"})
        aws_s3_obj.upload_file_obj_to_s3({'file_name': user_selected_file},
                                         s3_cred["credentials"]['base_bucket_name'],
                                         f'{user_id}/file_properties.json', 'json')
        return JsonResponse({"file_name": user_selected_file, "status": "success"})
    except Exception as e:
        return JsonResponse({"message": str(e)}, status=400)


@csrf_exempt
def gpt_graphical(request):
    if request.method == "POST":
        try:
            # Load CSV
            user_id = request.headers.get('X-User-ID')
            user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                                 f'{user_id}/file_properties.json', 'json')
            process_file_stat = check_processed_file(user_id, user_file)
            if not process_file_stat['status']:
                return JsonResponse({"message": process_file_stat["message"]})
            df = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                          f'{user_id}/{user_file["file_name"]}/processed_files/processed_data.csv', 'csv')

            # Generate CSV metadata
            csv_metadata = {"columns": df.columns.tolist()}
            metadata_str = ", ".join(csv_metadata["columns"])

            # User's query
            query = request.POST.get("prompt", "")

            # Prompt engineering for AI
            prompt_eng = (
                f"""You are an AI specialized in data analytics and visualization.
                        
                        The data for analysis is stored in a CSV file named 'data.csv', with the following attributes: 
                        {metadata_str}. Consider 'data.csv' as the sole data source for any analysis.
                        
                        Based on the user's query, generate Python code using Plotly to create the requested type of 
                        graph (e.g., bar, pie, scatter, etc.). If the user does not specify a graph type, 
                        determine whether to generate a line or bar graph based on the context.
                        
                        Ensure the graph meets the following criteria:
                        
                        Includes a title, axis labels (if applicable), and appropriate colors for data visualization.
                        Has a white background for both the plot and the paper.
                        Is visually appealing and provides sufficient context for understanding.
                        
                        The generated code must:
                        
                        Output a Plotly 'Figure' object stored in a variable named 'fig'.
                        Include the 'data' and 'layout' dictionaries required for the graph.
                        Be fully compatible with React.
                        User query: {query}
                """

            )
            trials = 3
            try:
                # Call AI to generate the code
                chat = generate_code(prompt_eng)
                print("Generated code from AI:")
                print(chat)

                # Check for valid Plotly code in the AI response
                if 'import' in chat:
                    namespace = {}
                    try:
                        # Execute the generated code
                        exec(chat, namespace)

                        # Retrieve the Plotly figure from the namespace
                        fig = namespace.get("fig")

                        if fig and isinstance(fig, Figure):
                            # Convert the Plotly figure to JSON
                            chart_data = fig.to_plotly_json()

                            # Recursively process the chart_data
                            chart_data_serializable = make_serializable(chart_data)

                            # Return the structured response to the frontend
                            return JsonResponse({
                                "chartData": chart_data_serializable
                            }, status=200)
                        else:
                            print("No valid Plotly figure found.")
                            return JsonResponse({"message": "No valid Plotly figure found."}, status=200)
                    except Exception as e:
                        error_message = f"There was an error while executing the code: {str(e)}"
                        print(error_message)
                        return JsonResponse({"message": error_message}, status=500)
                else:
                    print("Invalid AI response.")
                    return JsonResponse({"message": "AI response does not contain valid code."}, status=400)
            except Exception as e:
                pass
            trials -= 1

        except Exception as e:
            # Handle general exceptions
            error_message = f"An unexpected error occurred: {str(e)}"
            print(error_message)
            return JsonResponse({"message": error_message}, status=500)

    # Return a fallback HttpResponse for invalid request methods
    return HttpResponse("Invalid request method", status=405)


# Function to generate code from OpenAI API
def generate_code(prompt_eng):
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt_eng}
        ]
    )
    all_text = ""
    for choice in response.choices:
        message = choice.message
        chunk_message = message.content if message else ''
        all_text += chunk_message
    print(all_text)
    if "```python" in all_text:
        code_start = all_text.find("```python") + 9
        code_end = all_text.find("```", code_start)
        code = all_text[code_start:code_end]
    else:
        code = all_text
    return code


def data_processing(request):
    user_id = request.headers.get('X-User-ID')
    if request.method == 'GET':
        user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                             f'{user_id}/file_properties.json', 'json')
        process_file_stat = check_processed_file(user_id, user_file)
        if process_file_stat['status']:
            df = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                          f'{user_id}/{user_file["file_name"]}/processed_files/processed_data.csv', 'csv')
            user_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', f"user_{user_id}")
            file_path = os.path.join(user_dir, 'data.csv')
            df.to_csv(file_path, index=False)
            df = updatedtypes(df)
            if df.shape[0] > 0:
                nullvalues = df.isnull().sum().to_dict()
                parameters = list(nullvalues.keys())
                Count = list(nullvalues.values())
                total_missing = df.isnull().sum().sum()
                nor = df.shape[0]
                nof = df.shape[1]
                timestamp = 'N'
                boolean = 'N'
                categorical_vars = []
                boolean_vars = []
                numeric_vars = {}
                datetime_vars = []
                text_data = []
                td = None
                stationary = "NA"
                numfilter = ['25%', '50%', '75%']
                single_value_columns = [col for col in df.columns if df[col].nunique() == 1]
                df.drop(single_value_columns, axis=1, inplace=True)
                for i, j in df.dtypes.items():
                    if str(j) in ["float64", "int64"]:
                        data = df[i].describe().to_dict()
                        numeric_vars[i] = data
                    elif str(j) in ["object"] and i not in ['Remark']:
                        categorical_vars.append({i: df[i].nunique()})
                    elif str(j) in ["datetime64[ns]"]:
                        if i.upper() in ['DATE', "TIME", "DATE_TIME"]:
                            td = i
                        datetime_vars.append(i)
                    elif str(j) in ["bool"]:
                        boolean_vars.append(i)
                request.session['TimeSeriesColumns'] = datetime_vars
                # if 'Remark' in df.columns:
                #     text_data.append('Remark')
                istextdata = 'Y' if len(text_data) > 0 else 'N'
                if len(datetime_vars) > 0:
                    timestamp = 'Y'
                if td:
                    stationary = adf_test(df, td)
                catvalues = [{'Parameter': list(data.keys())[0], 'Count': list(data.values())[0]} for data in
                             categorical_vars]
                sentiment = checkSentiment(df, categorical_vars)
                if len(catvalues) > 0:
                    catdf = pd.DataFrame(catvalues)
                else:
                    catdf = pd.DataFrame()
                if len(numeric_vars) > 0:
                    numdf = pd.DataFrame(numeric_vars).T
                    numdf['ColumnName'] = numdf.index
                else:
                    numdf = pd.DataFrame()
                if len(boolean_vars) > 0:
                    boolean = 'Y'

                missingvalue = pd.DataFrame({"Parameters": parameters, 'Missing Value Count': Count})

                duplicate_records = df[df.duplicated(keep='first')].shape[0]
                df[datetime_vars] = df[datetime_vars].apply(pd.to_datetime, errors='coerce').apply(
                    lambda col: col.dt.strftime('%Y-%m-%d %H:%M:%S'))

                return JsonResponse(
                    {'nof_rows': str(nor), 'nof_columns': str(nof), 'timestamp': timestamp,
                     "single_value_columns": ",".join(single_value_columns) if len(
                         single_value_columns) > 0 else "NA",
                     'data': df.iloc[:100].to_json(),
                     "data description": df.dtypes.apply(lambda x: 'string' if x == 'object' else x.name).to_dict(),
                     "sentiment": sentiment,
                     "stationary": stationary,
                     'catdf': catdf.to_json(orient='records'),
                     'missing_data': str(total_missing),
                     'numdf': numdf.to_json(orient='records') if numdf.shape[0] > 0 else "No data", 'boolean': boolean,
                     'missingvalue': missingvalue.to_json(orient='records'),
                     'textdata': istextdata, 'duplicate_records': str(duplicate_records)
                     })

            else:
                return JsonResponse({"message": 'No data'})
        else:
            return HttpResponse(json.dumps(
                {'message': process_file_stat['message']}))
    else:
        return HttpResponse('Invalid Request')


def gen_graphs(request):
    try:
        user_id = request.headers.get('X-User-ID')
        user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                             f'{user_id}/file_properties.json', 'json')
        process_file_stat = check_processed_file(user_id, user_file)
        num_plots = 6
        num_rows = request.headers.get('num_of_rows')
        num_rows = int(num_rows) if num_rows else 100
        if process_file_stat['status']:
            df = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                          f'{user_id}/{user_file["file_name"]}/processed_files/processed_data.csv', 'csv')
            user_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', f"user_{user_id}")
            file_path = os.path.join(user_dir, 'plot_data.csv')
            df = updatedtypes(df)
            df = df.iloc[:num_rows]
            df.to_csv(file_path, index=False)
            plots_path = os.path.join(user_dir, 'plots')
            shutil.rmtree(plots_path, ignore_errors=True)
            os.makedirs(plots_path)
            sample_data = df.head(6)
            data_types_info = df.dtypes.to_string()
            result = {}
            while len(result) != num_plots:
                res = generate_dynamic_plots(file_path, plots_path, sample_data, data_types_info,
                                             num_plots - len(result))
                if res:
                    result.update(res)
            return JsonResponse({"status": "Success", "plots": result})
        else:
            return JsonResponse({"message": process_file_stat['message']})
    except Exception as e:
        print(e)
        return JsonResponse({"message": str(e)})


def generate_dynamic_plots(file_path, plots_path, sample_data, data_types_info, num_plots):
    # e. Saves the plot image to `{plots_path}` with the title as the filename (use `fig.write_image()`) save in both png  and html.
    prompt = f"""
                You are a data visualization expert and a Python Plotly developer.

                I will provide you with a sample dataset.

                Your task is to:
                1. Analyze the dataset and identify the top {num_plots} most insightful charts (e.g., trends, distributions, correlations, anomalies).
                2. Consider the data source as: {file_path}
                3. For each chart:
                   - Use a short, meaningful chart title (as the dictionary key).
                   - Write a brief insight about the chart as a Python comment (`# insight: ...`).
                   - Generate clean Python code that:
                     a. Creates the Plotly chart using the dataset,
                     b. Converts the figure to JSON using `fig.to_json()`,
                     c. Saves it in a dictionary using `chart_dict[<chart_title>] = {{'plot_data': ..., 'description': ...}}`
                     d. Wraps the chart generation and JSON conversion in a `try-except` block using `except Exception as e:` (capital E).
                     

                Instructions:
                - Return **only valid Python code**. Do **not** use markdown or bullet points.
                - Begin with any required imports and initialization of `chart_dict`.
                - - Do not use `except exception as e:`. It is incorrect Python. Always use `except Exception as e:` (capital E). Any other form is invalid and will cause a runtime error.
                - All explanations must be in valid Python comments (`# ...`)
                - Do not add any extra text outside Python code.
                - Use a diverse range of charts like: `line`, `bar`, `scatter`, `pie`, `box`, `heatmap`, `area`, `violin`, `Scatter3d`, `facet`, or animated plots.
                - Use **aggregations** like `.groupby(...).mean()`, `.count()`, `.sum()` where helpful.
                - - Apply **filters** when helpful, such as:
                  - Top N categories by value or count,
                  - Recent date ranges,
                  - Removal of nulls or extreme outliers.
                  - Top 5 categories by frequency or value

                - Explore **advanced Plotly features**, such as:
                  - `facet_row`, `facet_col` for comparison grids,
                  - multi-series (e.g. line or scatter with `color`=column),
                  - combo charts (e.g., bar + line together),
                  - rolling averages or moving means,
                  - violin plots to show distributions,
                  - 3D scatter plots (`px.scatter_3d`) where 3 numeric dimensions exist,
                  - animations (`animation_frame`, `animation_group`) if time-based trends are useful.
                - Aim for **high-value insights**, like:
                  - Seasonality or cyclic patterns,
                  - Equipment performing worse than average,
                  - Category-wise contribution to deficit or emissions,
                  - Any shocking anomalies or unexpected gaps.

                - Use this preview of the dataset:
                    {sample_data}

                - Column names and data types:
                    {data_types_info}

                IMPORTANT:
                    - If you ever write `except exception as e`, your answer is wrong and must be corrected before use.
                    - Ensure column names are used **exactly** as they appear in the dataset. **Do not change the case** or formatting of column names.
                    - Always use `df.columns = df.columns.str.strip()` after loading the dataset to handle unwanted spaces.
                    - After reading the CSV:
                    - Use `df.columns = df.columns.str.strip()` to remove leading/trailing spaces from column names.
                    - For datetime columns:
                        - Strip values using `df[col] = df[col].astype(str).str.strip()`
                        - Convert to datetime using `pd.to_datetime(df[col], errors='coerce', utc=True)`
                        - Drop rows where datetime conversion failed using `df.dropna(subset=[col], inplace=True)`
                    - Before using `.dt`, ensure the column is of datetime type using `pd.to_datetime()`.
                """

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]
    )
    processed_data = process_response(response)
    processed_data = re.sub(r'except\s+exception\s+as\s+e', 'except Exception as e', processed_data)
    print(processed_data)

    result = {}
    namespace = {}

    try:
        exec(processed_data, namespace)
    except Exception as e:
        print(e)

    return namespace.get('chart_dict')


@csrf_exempt
def kpi_prompt(request):
    try:
        user_id = request.headers.get('X-User-ID')
        if request.method == "POST":
            global KPI_LOGICS, checks
            KPI_LOGICS = defaultdict()
            checks = []
            prompt = request.POST.get('prompt')
            user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                                 f'{user_id}/file_properties.json', 'json')
            process_file_stat = check_processed_file(user_id, user_file)
            if not process_file_stat['status']:
                return JsonResponse({"message": process_file_stat["message"]})
            else:
                user_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', f"user_{user_id}")
                if os.path.exists(user_dir):
                    shutil.rmtree(user_dir)
                os.makedirs(user_dir, exist_ok=True)
                file_path = os.path.join(user_dir, 'data.csv')
                user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                                     f'{user_id}/{user_file["file_name"]}/input_files/file_properties.json', 'json')
                process_file_stat = check_processed_file(user_id, user_file)
                if not process_file_stat['status']:
                    return JsonResponse({"message": process_file_stat['message']})

                df = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                              f'{user_id}/{user_file["file_name"]}/processed_files/processed_data.csv', 'csv')
                df.to_csv(file_path, index=False)

                prompt_desc = (
                    f"You are analytics_bot. Analyse the data: {df.head()} and for the uer query {prompt}, "
                    f"generate kpis with response as KPI Name, Column and Logic. Response should be in python dictionary format  with kpi names as keys. In response dont add any other information just provide only the response dictionary"
                )
                n = 2
                while n > 0:
                    genai_res = generate_code(prompt_desc)
                    data_dict = json.loads(genai_res)
                    print("datadict", data_dict)
                    for key, value in data_dict.items():
                        value = {i.lower(): j for i, j in value.items()}
                        if 'kpi name' in value:
                            kpi_name = value['kpi name']
                        elif 'name' in value:
                            kpi_name = value["name"]
                        else:
                            kpi_name = key
                        KPI_LOGICS[key] = {
                            "KPI Name": kpi_name,
                            "Column": value["column"],
                            "Logic": value["logic"]
                        }
                    if KPI_LOGICS is not None:
                        if not os.path.exists('kpis.json'):
                            kpis_store = dict()
                        else:
                            with open('kpis.json', 'r') as fp:
                                kpis_store = json.load(fp)
                        with open('kpis.json', 'w') as fp:
                            kpis_store.update(KPI_LOGICS)
                            json.dump(kpis_store, fp)
                        break
                if os.path.exists(os.path.join('uploads', 'kpi_config.json')):
                    with open('uploads/kpi_config.json', 'r') as json_file:
                        kpis_dict = json.load(json_file)
                    for kpi in kpis_dict['Kpis']['kpi']:
                        KPI_LOGICS[kpi['KPI_Name']] = kpi
                        checks.append(kpi['KPI_Name'])
                return JsonResponse(
                    {
                        "kpis": KPI_LOGICS, "checks": checks}
                )
    except Exception as e:
        print(e)


@csrf_exempt
def mvt(request):
    user_id = request.headers.get('X-User-ID')
    user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                         f'{user_id}/file_properties.json', 'json')
    process_file_stat = check_processed_file(user_id, user_file)
    if process_file_stat['status']:
        data = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                        f'{user_id}/{user_file["file_name"]}/processed_files/mvt_data.json', 'json')
        return JsonResponse(
            {
                "df": data['data'],
                "Summary": data['summary'],
                "status": True
            }
        )
    else:
        return JsonResponse(
            {
                "message": process_file_stat['message'],
                "status": False
            }
        )


@csrf_exempt
def kpi_code(request):
    try:
        if request.method == "POST":
            kpi_list = request.POST.getlist("kpi_names")
            user_id = request.headers.get('X-User-id')
            paths, codes = generate_kpi_code(kpi_list, user_id)
            return JsonResponse({
                'plots': paths,
                'code': codes,
                "kpis": KPI_LOGICS,
                "checks": checks
            })
    except Exception as e:
        print(e)


@csrf_exempt
def models(request):
    try:
        user_id = request.headers.get('X-User-ID')
        user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                             f'{user_id}/file_properties.json', 'json')
        process_file_stat = check_processed_file(user_id, user_file)
        if not process_file_stat['status']:
            return JsonResponse({"message": process_file_stat["message"]})
        user_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', f"user_{user_id}")
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)
        os.makedirs(user_dir, exist_ok=True)
        file_path = os.path.join(user_dir, 'data.csv')

        df = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                      f'{user_id}/{user_file["file_name"]}/processed_files/processed_data.csv', 'csv')
        df.to_csv(file_path, index=False)
        single_value_columns = [col for col in df.columns if df[col].nunique() == 1]
        df.drop(single_value_columns, axis=1, inplace=True)
        numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
        if len(numeric_cols) < 1:
            return JsonResponse(
                {
                    "msg": "This dataset doesn't meet the modeling requirement "}
            )

        if request.method == 'POST':
            model_type = request.POST.get('model')
            col = request.POST.get('col')
            request.session['col_predict'] = col
            if model_type == 'RandomForest':
                stat, cols = random_forest(df, col, user_id)
                return JsonResponse(
                    {
                        'columns': list(df.columns),
                        "rf": True,
                        "status": stat,
                        "rf_cols": cols
                    })
            elif model_type == "K-Means":
                stat, clustered_data = kmeans_train(df, col, user_id)
                return JsonResponse(
                    {
                        'columns': list(df.columns),
                        "cluster": True,
                        "status": stat,
                        "clustered_data": clustered_data.to_json()
                    })
            elif model_type == "Arima":
                print("arima model")
                frequency = request.POST.get('frequency')
                tenure = request.POST.get('tenure')
                stat, data, img_data = arima_train(df, col, user_id,
                                                   {'time_unit': frequency, 'forecast_horizon': int(tenure)})
                if stat:
                    return JsonResponse(
                        {
                            'columns': list(df.columns),
                            "status": stat,
                            "arima": True,
                            "path": img_data,
                            'data': data.to_json()
                        })
                else:
                    return JsonResponse(
                        {
                            "status": stat,
                            'data': data.to_json(),
                            'msg': data
                        })
            elif model_type == 'OutlierDetection':
                out_res = outliercheck(df, col)

                return JsonResponse(
                    {
                        'columns': list(df.columns),
                        "status": True,
                        "processed_data": out_res,
                        "OutlierDetection": True
                    })
        else:
            return JsonResponse(
                {
                    'columns': list(df.columns)}
            )
    except Exception as e:
        print(e)
        return JsonResponse(
            {
                "msg": str(e)}
        )


def outliercheck(data, column):
    # Check if 'Target' column exists
    if column not in data.columns:
        raise ValueError("The column 'Target' does not exist in the CSV file.")

        # Calculate Q1 (25th percentile) and Q3 (75th percentile)
    Q1 = data[column].quantile(0.25)
    Q3 = data[column].quantile(0.75)

    # Calculate Interquartile Range (IQR)
    IQR = Q3 - Q1

    # Define the bounds for outliers
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR

    # Identify outliers
    outliers = data[(data[column] < lower_bound) | (data[column] > upper_bound)]
    summary_text = (
        f"<p>A total of <strong>{len(outliers)} outliers</strong> were detected.</p>"
        f"<p>These values may represent rare events, data entry errors, or legitimate but extreme variations.</p>"
        if len(outliers) > 0 else
        "<p> <strong>No outliers present</strong> in the dataset.</p>"
    )

    outlier_section = ""
    if len(outliers) > 0:
        outlier_table = outliers.to_html(index=False, border=1, classes='table table-striped', justify='center')
        outlier_section = f"<h4> Detected Outlier Values:</h4>{outlier_table}"

    output = f"""
    <div style="font-family:Arial,sans-serif; line-height:1.6;">
      <h3>Outlier Analysis Report for <code>{column}</code></h3>

      <p>We analyzed the distribution of the <code>{column}</code> values using the
      <strong>Interquartile Range (IQR)</strong> method to detect potential outliers.</p>

      <ul>
        <li><strong>Lower Bound:</strong> Values below <code>{lower_bound:.2f}</code></li>
        <li><strong>Upper Bound:</strong> Values above <code>{upper_bound:.2f}</code></li>
      </ul>

      <p>Any data points falling <strong>outside this range</strong> are considered <strong>outliers</strong>.</p>

      <hr/>

      <h4> Summary:</h4>
      {summary_text}
      {outlier_section}
    </div>
    """
    return output


def random_forest(data, target_column, user_id=None):
    try:
        if not aws_s3_obj.check_s3_file(s3_cred["credentials"]['base_bucket_name'],
                                        f'{user_id}/output/models/rf/{target_column}/deployment.json'):
            # Separate features and target
            X = data.drop(columns=[target_column])
            y = data[target_column]

            # Detect categorical and numerical features
            categorical_cols = X.select_dtypes(include=['object', 'category']).columns
            numerical_cols = X.select_dtypes(include=['int64', 'float64']).columns

            # Preprocessing pipelines for numerical and categorical data
            numerical_transformer = Pipeline(steps=[
                ('imputer', SimpleImputer(strategy='mean')),
                ('scaler', StandardScaler())])

            categorical_transformer = Pipeline(steps=[
                ('imputer', SimpleImputer(strategy='most_frequent')),
                ('onehot', OneHotEncoder(handle_unknown='ignore'))])

            # Combine preprocessing steps
            preprocessor = ColumnTransformer(
                transformers=[
                    ('num', numerical_transformer, numerical_cols),
                    ('cat', categorical_transformer, categorical_cols)
                ])

            # Choose Random Forest type based on target type
            if y.nunique() <= 5:  # Classification for few unique target values
                model_type = 'Classification'
                model = RandomForestClassifier(random_state=42)
            else:  # Regression for continuous target values
                model_type = 'Regression'
                model = RandomForestRegressor(random_state=42)

            # Create pipeline
            pipeline = Pipeline(steps=[
                ('preprocessor', preprocessor),
                ('model', model)
            ])

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            # Train the pipeline
            pipeline.fit(X_train, y_train)

            cv = min(5, len(X_test))

            # Evaluate the model using cross-validation
            scores = cross_val_score(pipeline, X_test, y_test, cv=cv)
            print(f"Model Performance (CV): {scores.mean():.4f} ± {scores.std():.4f}")

            aws_s3_obj.upload_pickle(pipeline, s3_cred["credentials"]['base_bucket_name'],
                                     f'{user_id}/output/models/rf/{target_column}/pipeline.pkl')

            print(f'Pipeline saved to: {os.path.join("models", "rf", target_column, "pipeline.pkl")}')

            aws_s3_obj.upload_file_obj_to_s3(
                {"columns": list(X_train.columns), "model_type": model_type, "Target_column": target_column},
                s3_cred["credentials"]['base_bucket_name'],
                f'{user_id}/output/models/rf/{target_column}/deployment.json', 'json')

            return True, list(X_train.columns)
        else:
            data = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                            f'{user_id}/output/models/rf/{target_column}/deployment.json', 'json')
            return True, data['columns']
    except Exception as e:
        print(e)
        return False, []


@csrf_exempt
def model_predict(request):
    try:
        user_id = request.headers.get('X-User-ID')
        if request.POST.get('form_name') == 'rf':
            res = {}
            for col in request.POST:
                if col == "targetColumn":
                    targetcol = request.POST[col]
                    continue
                res.update({col: request.POST[col]})
            del res['form_name']
            df = pd.DataFrame([res])
            user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                                 f'{user_id}/file_properties.json', 'json')
            pipeline = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                                f'{user_id}/{user_file["file_name"]}/output/models/rf/{targetcol}/pipeline.pkl', 'pkl')
            predictions = pipeline.predict(df)
            print(predictions)
            return JsonResponse(
                {
                    'columns': list(df.columns),
                    'rf_result': f"Predicted {targetcol} value is {round(predictions[0], 2)}"
                }
            )

    except Exception as e:
        print(e)
        return JsonResponse(
            {
                'columns': [],
                'rf_result': "NA"
            }
        )


@csrf_exempt
def gen_ai_bot(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests are allowed.'}, status=405)
    user_id = request.headers.get('X-User-id')

    # session = get_or_create_user_session(user_id)
    try:

        user_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', f"user_{user_id}")
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)
        os.makedirs(user_dir, exist_ok=True)
        file_path = os.path.join(user_dir, 'data.csv')
        user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                             f'{user_id}/file_properties.json', 'json')
        process_file_stat = check_processed_file(user_id, user_file)
        if not process_file_stat['status']:
            return JsonResponse({"message": process_file_stat["message"]})

        df = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                      f'{user_id}/{user_file["file_name"]}/processed_files/processed_data.csv', 'csv')
        df.to_csv(file_path, index=False)

        metadata_str = ", ".join(df.columns.tolist())
        sample_data = df.head(2).to_dict(orient='records')

        # Handle both form-encoded and JSON payloads
        try:
            body = json.loads(request.body)
            prompt = body.get('prompt')
        except json.JSONDecodeError:
            prompt = request.POST.get('prompt')

        if not prompt:
            return JsonResponse({'error': 'Prompt is required.'}, status=400)

        if 'forecast' in prompt.lower():
            bot_data = extract_forecast_details_arima(prompt, df.columns)
            stat, data, img_data = arima_train(df, bot_data['target_variable'], user_id, bot_data)
            # ChatMessage.objects.create(
            #     session=session,
            #     query=prompt,
            #     response={"data": data, "plot": img_data},
            #     token_count=len(data)
            # )
            return JsonResponse({
                'data': data.to_json(),
                'plot': img_data
            }, status=200)
        elif 'predict' in prompt.lower():
            try:
                bot_data = extract_forecast_details_rf(prompt, df.columns)
                if len(bot_data.get('missing_columns')) > 0:
                    return JsonResponse({
                        'text_pre_code_response': f'Prediction failed due to missing fields: {bot_data.get("missing_columns")}.'
                                                  f'please retry with all the required inputs '
                    }, status=200)
                if not aws_s3_obj.check_s3_file(s3_cred["credentials"]['base_bucket_name'],
                                                f'{user_id}/{user_file["file_name"]}/output/models/rf/{bot_data["target_column"]}/deployment.json'):
                    print("userid", user_id)
                    _ = random_forest(df, bot_data.get('target_column'), user_id)
                df = pd.DataFrame([bot_data.get('features')])
                loaded_pipeline = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                                           f'{user_id}/{user_file["file_name"]}/output/models/rf/{bot_data["target_column"]}/pipeline.pkl',
                                                           'pkl')
                predictions = loaded_pipeline.predict(df)
                print(predictions)
                return JsonResponse({
                    "text_pre_code_response": f"Predicted {bot_data.get('target_column')} value is {round(predictions[0], 2)}"})
            except Exception as e:
                return JsonResponse({"text_pre_code_response": str(e)})
        else:

            system_prompt = f"""You are an AI specialized in data analytics and visualization. The data for analysis is 
            stored in a CSV file stored at {file_path}, with the following attributes: {metadata_str} and sample data as 
            {sample_data}.

            Follow these rules while responding to user queries:

            1. Strictly use {file_path} as the data source path without stating any limitations or disclaimers about file access.
            2. Data Analysis: If the query requires numerical or tabular insights, extract relevant data from 
            data.csv, perform necessary calculations, and provide a concise summary. Store the result in text_output.
            3. Visualization: If the query requires a graph, generate Python code using Plotly with fig as output.
            4. Forecasting: Generate forecast using ARIMA and store results in text_output and plot in fig.
            """
            messages = [{"role": "system", "content": system_prompt}]
            # history = ChatMessage.objects.filter(session=session).order_by('timestamp')
            chat_pairs = []
            # for msg in history:
            #     chat_pairs.append({"role": "user", "content": msg.query})
            #     chat_pairs.append({"role": "assistant", "content": msg.response})

            user_input = {"role": "user", "content": prompt}
            while True:
                combined = messages + chat_pairs + [user_input]
                token_count = count_tokens(combined)
                if token_count < MAX_TOKENS - TOKEN_BUFFER:
                    break

                if len(chat_pairs) <= 4:
                    # Can't trim further, just drop oldest pair
                    chat_pairs = chat_pairs[2:]
                    continue

                # Summarize oldest 4 messages (2 pairs)
                oldest_msgs = chat_pairs[:4]
                oldest_text = "\n".join(
                    f"{m['role']}: {m['content']}" for m in oldest_msgs
                )
                summary = summarize_text(oldest_text)

                # Replace those oldest messages with the summary as one user message
                chat_pairs = [{"role": "user", "content": summary}] + chat_pairs[4:]
            result = {}
            try:
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=messages + chat_pairs + [user_input],
                    temperature=0.3
                )
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)

            reply = response.choices[0].message.content
            total_tokens_used = response.usage.total_tokens if hasattr(response, 'usage') else token_count

            # Save chat message in DB
            # ChatMessage.objects.create(
            #     session=session,
            #     query=prompt,
            #     response=reply,
            #     token_count=total_tokens_used
            # )

            pre_code_text, post_code_text, code = process_genai_response(response)
            result.update({
                'text_pre_code_response': pre_code_text,
                'text_post_code_response': post_code_text
            })

            if 'import' in code:
                namespace = {}
                try:
                    exec(code, namespace)
                    result['text_output'] = namespace.get('text_output')

                    fig = namespace.get('fig')
                    if fig and isinstance(fig, Figure):
                        result['chart_response'] = fig.to_plotly_json()

                except Exception as e:
                    return JsonResponse({'message': str(e)}, status=500)

            return JsonResponse(result, status=200)

    except Exception as e:
        return JsonResponse({'message': str(e)}, status=500)


def extract_forecast_details_arima(prompt, column_names):
    try:
        system_prompt = f""" You are an AI assistant that extracts forecast details from a user's prompt. Given a 
        natural language input and the following column names from the input data, return the following in JSON format:
    
            1. "target_variable" - The thing being forecasted (e.g., "sales", "revenue"). - If the target variable is 
            misspelled or ambiguous, try to match it to the closest column name from the list below. 2. 
            "forecast_horizon" - The number of time steps. 3. "time_unit" - The unit of time (days, months, years).
    
            Available column names: {', '.join(column_names)}
    
            Example Outputs:
            - Input: "Forecast the sales data for 5 years."
              Output: {{"target_variable": "sales", "forecast_horizon": 5, "time_unit": "years"}}
    
            - Input: "Can you predict electricity demand for the next 12 months?"
              Output: {{"target_variable": "electricity demand", "forecast_horizon": 12, "time_unit": "months"}}
    
            - Input: "I want to predict CO2 levels for 7 days."
              Output: {{"target_variable": "CO2 levels", "forecast_horizon": 7, "time_unit": "days"}}
    
            Ensure that the "target_variable" matches one of the available column names, even if the user misspells it.
            """
        forecast_details = ''
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0  # Make it deterministic
        )
        for choice in response.choices:
            message = choice.message
            chunk_message = message.content if message else ''
            forecast_details += chunk_message
        print(forecast_details)

        return eval(forecast_details)

    except Exception as e:
        print(e)


def extract_forecast_details_rf(prompt, column_names):
    try:
        system_prompt = f"""
            You are an AI assistant that extracts machine learning input features and the target variable from a user's natural language prompt.
            
            You are provided a list of available column names: {', '.join(column_names)}.
            
            Your job is to:
            1. **Correct Spelling**: If any feature or target column is misspelled, match it to the closest name from the provided column list.
            2. **Extract Features**: Identify which features and their values are mentioned in the input.
            3. **Detect Missing Features**: If some required features are not mentioned, list them under "missing_columns".
            4. **Identify Target Column**: If the user specifies a column as the one to be predicted or forecasted, include it as "target_column".
            5. **Always Return All Three Fields**: Even if one or more are empty, the response **must always** contain "features", "missing_columns", and "target_column".

            ### Expected Output Formats:
            
            #### a) All features and target column provided:
            Input: "Predict CO2 level. The temperature is 25 and humidity is 45."
            Output:
            {{
              "features": {{
                "temperature": 25,
                "humidity": 45
              }},
              "missing_columns":[],
              "target_column": "CO2 level"
            }}
            
            #### b) Some features missing:
            Input: "I want to predict pressure. Set humidity to 50."
            Output:
            {{
              "features": {{
                "humidity": 50
              }},
              "missing_columns": ["temperature", "CO2 level"],
              "target_column": "pressure"
            }}
            
            #### c) Misspelled entries:
            Input: "Predict temprature using humdity = 60 and presure = 1000"
            Output:
            {{
              "features": {{
                "humidity": 60,
                "pressure": 1000
              }},
              "missing_columns": ["CO2 level"],
              "target_column": "temperature"
            }}
            
            ### Notes:
            - Always correct any misspelled column names to the closest match in the available list.
            - Use numeric types for numeric values, not strings.
            - If the target column is not explicitly provided, leave "target_column" as null or omit it.
        """

        predict_details = ''
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0  # Make it deterministic
        )
        for choice in response.choices:
            message = choice.message
            chunk_message = message.content if message else ''
            predict_details += chunk_message
        print(predict_details)

        return eval(predict_details)

    except Exception as e:
        print(e)


def process_genai_response(response):
    all_text = ""
    text_post_code = ''
    code_start = -1
    code_end = -1
    for choice in response.choices:
        message = choice.message
        chunk_message = message.content if message else ''
        all_text += chunk_message
    print(all_text)
    if "```python" in all_text:
        code_start = all_text.find("```python") + 9
        code_end = all_text.find("```", code_start)
        code = all_text[code_start:code_end]
        text_pre_code = all_text[:code_start - 9]
        text_post_code = all_text[code_end:]
    else:
        code = ''
        text_pre_code = all_text
        text_post_code = ''
    return text_pre_code, text_post_code, code


def kmeans_train(data, col, user_id):
    try:
        # Identify categorical and numerical columns
        categorical_columns = data.select_dtypes(include=['object', 'category']).columns.tolist()
        numerical_columns = data.select_dtypes(include=[np.number]).columns.tolist()

        # Handle missing values (if any)
        imputer = SimpleImputer(strategy='mean')
        data[numerical_columns] = imputer.fit_transform(data[numerical_columns])

        aws_s3_obj.upload_pickle(imputer, s3_cred["credentials"]['base_bucket_name'],
                                 f'{user_id}/output/models/kmeans/{col}/imputer.pkl')

        # Build a transformer for preprocessing: scaling numerical columns and encoding categorical columns
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), numerical_columns),  # Standard scaling for numerical columns
                ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_columns)
                # One-Hot encoding for categorical columns
            ])

        # Apply preprocessing and fit KMeans
        X = preprocessor.fit_transform(data)

        # Find the optimal k using the elbow method with KMeans
        inertia = []
        K_range = range(1, 11)
        for k in K_range:
            kmeans = KMeans(n_clusters=k, random_state=0)
            kmeans.fit(X)
            inertia.append(kmeans.inertia_)

        # Determine the optimal k
        optimal_k = find_elbow_point(inertia)
        print('Optimal number of clusters (k) based on the Elbow Method:', optimal_k)

        # Initialize KMeans with the optimal number of clusters
        kmeans = KMeans(n_clusters=optimal_k, random_state=0)

        # Fit KMeans to the preprocessed data
        kmeans.fit(X)
        user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                             f'{user_id}/file_properties.json', 'json')
        aws_s3_obj.upload_pickle(kmeans, s3_cred["credentials"]['base_bucket_name'],
                                 f'{user_id}/{user_file["file_name"]}/output/models/kmeans/{col}/kmeans_model.pkl')
        aws_s3_obj.upload_pickle(preprocessor, s3_cred["credentials"]['base_bucket_name'],
                                 f'{user_id}/{user_file["file_name"]}/output/models/kmeans/{col}/preprocessor.pkl')

        # Add cluster labels to the original data
        data['Cluster'] = kmeans.labels_
        return True, data
    except Exception as e:
        print(e)
        return False, data


def arima_train(data, target_col, user_id, bot_query=None):
    try:
        # Identify date column by checking for datetime type
        date_column = None
        results = {}
        user_file = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                             f'{user_id}/file_properties.json', 'json')
        print("Path:", f'{user_id}/{user_file["file_name"]}/output/models/Arima/{target_col}/{target_col}_results.json')
        if not aws_s3_obj.check_s3_file(s3_cred["credentials"]['base_bucket_name'],
                                        f'{user_id}/{user_file["file_name"]}/output/models/Arima/{target_col}/{target_col}_results.json'):
            for col in data.columns:
                if data.dtypes[col] == 'object':
                    try:
                        # Attempt to convert column to datetime
                        pd.to_datetime(data[col])
                        date_column = col
                        break
                    except (ValueError, TypeError):
                        continue
            if not date_column:
                raise ValueError("No datetime column found in the dataset.")
            print(date_column)
            # Set the date column as index
            data[date_column] = pd.to_datetime(data[date_column])
            data.set_index(date_column, inplace=True)

            try:
                data_actual = data[[target_col]]
                data_actual.reset_index(inplace=True)
                data_actual.columns = ["datetime", 'value']
                data_actual.set_index("datetime", inplace=True)
                train_frequency = check_data_frequency(data_actual)

                train_models(data_actual, target_col, user_id)

                aws_s3_obj.upload_file_obj_to_s3(
                    {'data_freq': train_frequency, 'date_column': date_column,
                     'end_date': f'{data_actual.index[-1]}'},
                    s3_cred["credentials"]['base_bucket_name'],
                    f'{user_id}/{user_file["file_name"]}/output/models/Arima/{target_col}/{target_col}_results.json', 'json')

            except Exception as e:
                print(e)

        frequency = bot_query['time_unit']
        periods = bot_query['forecast_horizon']
        print("downloading filess")
        loaded_model = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                                f'{user_id}/{user_file["file_name"]}/output/models/Arima/{target_col}/{frequency}/best_model.pkl',
                                                'pkl')

        freq_map = {
            'hours': 'H',
            'days': 'D',
            'weeks': 'W',
            'months': 'M',
            'quarters': 'QS',
            'years': 'YS'
        }

        forecasted_data = arima_forecast(loaded_model, periods, freq_map[frequency], target_col, user_id)
        print(forecasted_data)

        result_graph = plot_graph(forecasted_data, target_col)

        print(f"Results saved")
        return True, forecasted_data, result_graph

    except Exception as e:
        print(e)
        return False, str(e), ''


def load_pipeline(save_path="model_pipeline.pkl"):
    # Load the saved pipeline
    pipeline = joblib.load(save_path)
    print(f"Pipeline loaded from: {save_path}")
    return pipeline


def find_elbow_point(inertia_values):
    # Calculate the rate of change between successive inertia values
    changes = np.diff(inertia_values)
    # Identify the elbow as the point where change starts to decrease
    elbow_point = np.argmin(np.abs(np.diff(changes))) + 1
    return elbow_point


def plot_graph(data, target_col):
    try:

        # Create Plotly figure
        fig = go.Figure()
        try:
            data['date'] = data['date'].dt.strftime('%Y-%m-%d')
        except Exception as e:
            print(e)
        # Actual Data Line
        fig.add_trace(go.Scatter(
            x=data['date'], y=data["forecasted_value"],
            mode='lines+markers', name='Forecast',
            line=dict(color='blue'), marker=dict(symbol='circle')
        ))

        # Forecast Data Line
        # fig.add_trace(go.Scatter(
        #     x=forecast_dates, y=forecast_values,
        #     mode='lines+markers', name='Forecast',
        #     line=dict(color='orange', dash='dash'), marker=dict(symbol='x')
        # ))

        # Layout Settings
        fig.update_layout(
            title=f'Forecasted {target_col} values Over Time',
            xaxis_title='Date',
            yaxis_title='Values',
            xaxis=dict(tickangle=-45, type='category', tickformat='%Y-%m-%d'),
            template="plotly_white",
            width=1000, height=600
        )

        # Convert figure to Base64 Image
        fig.show()
        return fig.to_json()

    except Exception as e:
        print(e)
        return str(e)


def generate_kpi_code(kpi_list, user_id):
    try:
        user_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', f"user_{user_id}")
        data_file_path = os.path.join(user_dir, 'data.csv')
        df = pd.read_csv(data_file_path)
        df = updatedtypes(df)
        codes = {}
        paths = {}
        if os.path.exists(os.path.join(os.getcwd(), f'static/charts')):
            shutil.rmtree(os.path.join(os.getcwd(), f'static/charts'))
        os.makedirs(f'static/charts', exist_ok=True)

        for kpi in kpi_list:
            prompt_desc = (
                f"""You are ai_bot.Make sure to read the data from the path {data_file_path} which is of csv format and with example data as {df.head()} and generate Python code with KPI details as {KPI_LOGICS[kpi]}. 
                    Ensure the result is stored in a variable named 'result'.  Use Plotly to generate a suitable interactive plot for the obtained result. The type of plot should be chosen based on the structure of 'result' (e.g., bar plot for categorical/numeric summaries, line plot for time series, scatter plot for correlations, etc.). 
                    Instead of saving the plot, **convert the Plotly figure to a JSON representation** using `fig.to_json()` and return it as the output.
                    If the length of 'result' is 1, use a thin bar width and strictly set the x-axis limit to [-0.5, 0.5]."""
            )
            code = ''

            try:
                temp, chart_data = generate_code2(prompt_desc)
                code += temp
                paths[kpi] = chart_data
            except Exception as e:
                print(e)
                code += f'Code generation failed for {kpi}'
            codes[kpi] = "<b>" + kpi.capitalize() + "</b>" + "\n" + mark_safe(code) + '\n'

        return paths, codes
    except Exception as e:
        print(e)


@csrf_exempt
def generate_code2(prompt_eng):
    trials = 2
    chart_data = {}
    try:
        while trials > 0:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": prompt_eng}
                ]
            )
            all_text = ""

            # Display generated content dynamically
            for choice in response.choices:
                print(f"Debug - choice structure: {choice}")  # Debugging line
                message = choice.message
                print(f"Debug - message structure: {message}")  # Debugging line
                chunk_message = message.content if message else ''
                all_text += chunk_message

            print(all_text)
            python_chuncks = all_text.count("```python")
            idx = 0
            code = ''
            for i in range(python_chuncks):
                code_start = all_text[idx:].find("```python") + 9
                code_end = all_text[idx:].find("```", code_start)
                code += all_text[idx:][code_start:code_end]
                idx = code_end
            print(code)
            try:
                local_vars = {}
                exec(code, {}, local_vars)
                fig = local_vars.get("fig")

                if fig and isinstance(fig, Figure):
                    # Convert the Plotly figure to JSON
                    chart_data = fig.to_plotly_json()
                code += f"\n <b>Output: {local_vars['result']}</b> \n <hr>"
                return code, make_serializable(chart_data)
            except Exception as e:
                print(e)
                trials -= 1
    except Exception as e:
        print(e)


def plot_numeric(numeric_vars, dataframe):
    df = dataframe
    plots = {}

    for i in list(numeric_vars.keys()):
        # Create traces
        fig = go.Figure()

        # Add bar plot
        fig.add_trace(go.Bar(x=np.arange(len(df[i])), y=df[i], name=i, marker_color='blue'))

        # Add min, max, and median reference lines
        fig.add_hline(y=df[i].min(), line=dict(color='blue', dash='dash'), annotation_text='Min',
                      annotation_position="top left")
        fig.add_hline(y=df[i].max(), line=dict(color='red', dash='dash'), annotation_text='Max',
                      annotation_position="top left")
        fig.add_hline(y=df[i].median(), line=dict(color='green', dash='dash'), annotation_text='Median',
                      annotation_position="top left")

        # Customize layout
        fig.update_layout(
            title=i,
            xaxis_title="Index",
            yaxis_title=i,
            yaxis=dict(
                tickmode="array",
                tickvals=df[i].unique(),
            ),
            template="plotly_white",
            width=1000,  # Equivalent to figsize=(20, 10)
            height=500
        )
        # fig_data = generate_gpt_insight_payload(fig)
        # insights = get_graph_insights(fig_data)
        # Convert figure to JSON for rendering in web applications
        # plots[i] = {
        #     "plot":make_serializable(fig.to_json()),
        #     'insights':insights
        # }
        plots[i] = make_serializable(fig.to_json())

    return plots


def plot_categorical(categorical_vars, dataframe):
    df = dataframe
    plots = {}

    for i in categorical_vars:
        name = [k[0] for k in df[list(i)].value_counts().index.tolist()]
        count = df[list(i)].value_counts().values.tolist()

        # Create a pie chart using Plotly
        fig = px.pie(
            names=name,
            values=count,
            title=list(i)[0],
            color_discrete_sequence=px.colors.qualitative.Bold,
            hole=0.3  # Adjust to create a donut chart if needed
        )

        # Convert figure to JSON for web rendering
        # fig_data = generate_gpt_insight_payload(fig)
        # insights = get_graph_insights(fig_data)
        # # Convert figure to JSON for rendering in web applications
        # plots[list(i)[0]] = {
        #     "plot": make_serializable(fig.to_json()),
        #     'insights': insights
        # }
        plots[list(i)[0]] = make_serializable(fig.to_json())

    return plots


def plot_wordCloud(text_data, dataframe):
    df = dataframe
    plots = {}

    for i in text_data:
        # Generate word cloud
        text = " ".join(cat for cat in df[i])
        wordcloud = WordCloud(collocations=False, background_color='white').generate(text)

        # Convert to an image
        img = io.BytesIO()
        wordcloud.to_image().save(img, format="PNG")
        img_base64 = base64.b64encode(img.getvalue()).decode("utf-8")

        # Create a Plotly figure with the word cloud image
        fig = go.Figure()
        fig.add_layout_image(
            dict(
                source=f"data:image/png;base64,{img_base64}",
                x=0.5,
                y=0.5,
                xref="paper",
                yref="paper",
                sizex=1,
                sizey=1,
                xanchor="center",
                yanchor="middle",
                layer="below"
            )
        )

        # Layout settings
        fig.update_layout(
            title=i,
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            width=800, height=500,
        )

        # Convert figure to JSON for web rendering
        plots[i] = fig.to_json()

    return plots


def get_graph_insights(data):
    system_prompt = """
            You are a data analyst AI assistant. When given a Plotly chart's metadata and data (such as title, type, axes, and data points), your job is to:
        
        1. Clearly describe the chart type and its purpose.
        2. Summarize key patterns or trends in the data (increases, decreases, clusters, outliers).
        3. Highlight important statistics (peaks, valleys, averages, or changes over time).
        4. Identify any anomalies, seasonality, or cyclical patterns if present.
        5. Return your observations in clear, business-friendly language.
        
        Be concise but insightful. If a user asks follow-up questions, respond as a data analyst would. Do not guess about what is not shown in the data.

    """
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user",
                 "content": f"Here is the chart data:\n```json\n{json.dumps(data, indent=2, default=str)}\n```"}]
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.3
        )
        return response.choices[0].message.content

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def generate_gpt_insight_payload(fig, fallback_title: str = "Chart"):
    """
    Extracts key chart info from Plotly (Bar, Pie, Word Cloud-style scatter).
    Returns a structured payload ready for GPT analysis.
    """
    chart_type = None
    data_points = []
    summary_stats = {}
    reference_lines = {}

    # Determine chart type
    trace = fig.data[0] if fig.data else None
    if not trace:
        return {"chart_type": "Empty Figure", "data_points": [], "summary_stats": {}}

    title = fig.layout.title.text if fig.layout.title.text else fallback_title

    # === BAR CHART ===
    if trace.type == "bar":
        x = list(trace.x)
        y = list(trace.y)
        series = pd.Series(y)

        chart_type = "Bar Chart"
        data_points = list(zip(x, y))
        reference_lines = {
            "min": round(series.min(), 2),
            "max": round(series.max(), 2),
            "median": round(series.median(), 2)
        }
        summary_stats = {
            "mean": round(series.mean(), 2),
            "std_dev": round(series.std(), 2),
            "missing_count": int(series.isnull().sum()),
            "unique_values": int(series.nunique())
        }

    # === PIE CHART ===
    elif trace.type == "pie":
        labels = list(trace.labels)
        values = list(trace.values)

        chart_type = "Pie Chart"
        data_points = list(zip(labels, values))
        summary_stats = {
            "total": round(sum(values), 2),
            "category_count": len(labels),
            "largest_category": labels[values.index(max(values))],
            "smallest_category": labels[values.index(min(values))]
        }

    # === WORD CLOUD (scatter with text + size) ===
    elif trace.type == "scatter" and getattr(trace, 'mode', '') == "text":
        words = list(trace.text)
        sizes = list(trace.marker.size)

        chart_type = "Word Cloud"
        data_points = list(zip(words, sizes))
        summary_stats = {
            "unique_words": len(words),
            "most_prominent_word": words[sizes.index(max(sizes))],
            "least_prominent_word": words[sizes.index(min(sizes))]
        }

    else:
        chart_type = "Unsupported"
        summary_stats = {"note": "Only bar, pie, and word cloud (scatter-text) are supported."}

    return {
        "chart_type": chart_type,
        "title": title,
        "data_points": data_points,
        "reference_lines": reference_lines,
        "summary_stats": summary_stats
    }


def updatedtypes(df):
    datatypes = df.dtypes
    for col in df.columns:
        if datatypes[col] == 'object':
            try:
                df[col] = pd.to_datetime(df[col])
            except Exception as e:
                pass
    return df


def adf_test(df, kpi):
    df_t = df.set_index(kpi)

    for col in df_t.columns:
        # Check if the column name is not in the specified list and is numeric
        if col.upper() not in ['DATE', 'TIME', 'DATE_TIME'] and pd.api.types.is_numeric_dtype(df_t[col]):
            if df_t[col].nunique() > 1:
                dftest = adfuller(df_t[col], autolag='AIC')
                statistic_value = dftest[0]
                p_value = dftest[1]
                if (p_value > 0.5) and all([statistic_value > j for j in dftest[4].values()]):
                    return "Y"
            else:
                break
    return "N"


def checkSentiment(df, categorical):
    sentiment = 'N'
    for i in categorical:
        # print([j for j in df[i]])
        data = ' '.join([str(j) for j in df[list(i.keys())[0]]]).upper()
        if ('GOOD' in data) | ('BAD' in data) | ('Better' in data):
            sentiment = "Y"
    return sentiment


def is_integer_like(series):
    return pd.api.types.is_numeric_dtype(series) and \
        series.dropna().apply(lambda x: float(x).is_integer()).all()


def handle_missing_data(df):
    try:
        ignore_types = ['object', 'string', 'timedelta', 'complex']
        ignored_columns_info = {}

        # Identify numeric and datetime columns
        numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
        date_time_cols = df.select_dtypes(include=['datetime64']).columns
        ignored_cols = df.select_dtypes(include=ignore_types).columns
        int_like_cols = [col for col in numeric_cols if is_integer_like(df[col])]

        for col in ignored_cols:
            ignored_columns_info[col] = f"Ignored because of optional data"

        # Impute numeric columns and track which cells were imputed
        imputer = KNNImputer(n_neighbors=5)
        imputed_numeric = imputer.fit_transform(df[numeric_cols])
        imputed_numeric_df = pd.DataFrame(imputed_numeric, columns=numeric_cols).round(2)

        for col in numeric_cols:
            if col in int_like_cols:
                imputed_numeric_df[col] = imputed_numeric_df[col].round().astype("Int64")

        # Mark imputed cells (True if the original cell was NaN)
        imputed_flags = df[numeric_cols].isnull()
        imputed_flags = imputed_flags.applymap(lambda x: x if x else False)

        # Update DataFrame with imputed values
        df[numeric_cols] = imputed_numeric_df

        for col in df.select_dtypes(include='category').columns:
            if df[col].isnull().any():
                mode_val = df[col].mode().iloc[0] if not df[col].mode().empty else "Unknown"
                df[col].fillna(mode_val, inplace=True)
                imputed_flags[col] = df[col].isnull()
        for col in df.select_dtypes(include='bool').columns:
            if df[col].isnull().any():
                df[col].fillna(df[col].mode().iloc[0], inplace=True)

        # Handle datetime columns by forward filling missing values
        for col in date_time_cols:
            df[col] = pd.to_datetime(df[col])
            time_diffs = df[col].diff().dropna()
            avg_diff_sec = time_diffs.mean().total_seconds()
            minute_sec = 60
            hour_sec = 3600
            day_sec = 86400
            month_sec = day_sec * 30.44
            year_sec = day_sec * 365.25

            if avg_diff_sec < hour_sec:
                time_unit = "minutes"
                avg_diff = pd.Timedelta(minutes=avg_diff_sec / minute_sec)
            elif avg_diff_sec < day_sec:
                time_unit = "hours"
                avg_diff = pd.Timedelta(hours=avg_diff_sec / hour_sec)
            elif avg_diff_sec < month_sec:
                time_unit = "days"
                avg_diff = pd.Timedelta(days=avg_diff_sec / day_sec)
            elif avg_diff_sec < year_sec:
                time_unit = "months"
                avg_diff = pd.DateOffset(months=round(avg_diff_sec / month_sec))
            else:
                time_unit = "years"
                avg_diff = pd.DateOffset(years=round(avg_diff_sec / year_sec))

            for i in range(1, len(df)):
                if pd.isnull(df[col].iloc[i]):
                    df.loc[i, col] = df[col].iloc[i - 1] + avg_diff
                    imputed_flags.loc[i, col] = True

            imputed_flags.fillna(False, inplace=True)

        # Convert the DataFrame into a JSON-serializable format with flags
        data = []

        for _, row in df.iterrows():
            row_data = {}
            for col in df.columns:
                row_data[col] = {
                    "value": row[col].strftime('%Y-%m-%d %H:%M:%S') if isinstance(row[col], pd.Timestamp) else row[col],
                    "is_imputed": str(imputed_flags[col].get(_, False)) if col in imputed_flags else str(False)
                    # Check if cell was imputed
                }
            data.append(row_data)
        missing_values_summary = summarize_missing_values(imputed_flags)
        missing_values_summary["ignored_columns"] = ignored_columns_info
        return df, data, missing_values_summary
    except Exception as e:
        print(e)


def summarize_missing_values(df):
    try:
        # 1. Total number of missing values
        total_missing = df.sum().sum()

        # 2. Columns with any missing values
        columns_with_missing = df.columns[df.any()].tolist()

        # 3. Count of missing values per column
        missing_count_per_column = df.sum()

        # 4. Percentage of missing values per column (optional)
        missing_percentage = df.mean() * 100

        # Final summary
        summary = {
            "total_missing_values": int(total_missing),
            "columns_with_missing": columns_with_missing,
            "missing_count_per_column": missing_count_per_column.to_dict(),
            "missing_percentage_per_column": missing_percentage.round(2).to_dict()
        }
        return summary
    except Exception as e:
        print(e)
        return {}


def detect_and_parse_date(value):
    """
    Detects and converts dates in multiple formats, including:
    - MM-DD-YYYY
    - DD-MM-YYYY
    - MM/DD/YYYY
    - DD/MM/YYYY
    - YYYY-MM-DD
    """
    if pd.isna(value) or not isinstance(value, str) or value.strip() == "":
        return pd.NaT  # Handle missing values safely

    try:
        # Check if it's a date with hyphens or slashes
        if re.match(r"^\d{1,2}[-/]\d{1,2}[-/]\d{4}$", value):
            day_first = False  # Assume MM-DD-YYYY first

            # Check for an ambiguous case (day > 12) → Must be DD-MM-YYYY
            parts = re.split(r"[-/]", value)
            month, day, year = int(parts[0]), int(parts[1]), int(parts[2])
            if day > 12:
                day_first = True  # Switch to DD-MM-YYYY

            # Parse with detected format
            return dateutil.parser.parse(value, dayfirst=day_first)

        # Otherwise, use default dateutil parsing
        return dateutil.parser.parse(value)

    except ValueError:
        return pd.NaT  # Return NaT if parsing fails


def convert_to_datetime(df):
    """
    Converts object (string) columns containing dates to datetime format.
    """
    for col in df.columns:
        if df[col].dtype == "object":  # Process only string columns
            if df[col].str.contains(r"\d{1,4}[-/]\d{1,2}[-/]\d{1,4}", na=False).any():
                df[col] = df[col].apply(detect_and_parse_date)

    return df


def process_missing_data(df):
    df = convert_to_datetime(df)
    df, html_df, summary = handle_missing_data(df)
    return df, html_df, summary


def encode_image_to_base64(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode("utf-8")


def additional_plots(df):
    plots = {}
    try:
        df["hover_text"] = df.apply(lambda row:
                                    f"Date: {row['Date']}<br>EquipID: {row['EquipID']}<br>CO2 Emission: {row['CO2 Emission - Actual']}",
                                    axis=1)
        # Create 3D scatter plot
        fig = go.Figure(data=[go.Scatter3d(
            x=df["Date"],  # Date converted to numerical values
            y=df["EquipID"],
            z=df["CO2 Emission - Actual"],
            mode='markers',
            marker=dict(
                size=8,
                color=df["CO2 Emission - Actual"],  # Color based on CO2 emission
                colorscale='Viridis',
                opacity=0.8
            ),
            text=df["hover_text"],  # Add custom hover text
            hoverinfo="text"

        )])

        # Update layout
        fig.update_layout(
            title="CO2 Emissions",
            scene=dict(
                xaxis_title="Days since Start (Date)",
                yaxis_title="Equipment ID",
                yaxis=dict(
                    tickmode="array",
                    tickvals=df["EquipID"].unique(),  # Ensure only integer Equipment IDs are shown
                ),
                zaxis_title="CO2 Emission (Actual)"
            )
        )

        # Show the interactive 3D plot

        # fig_data = generate_gpt_insight_payload(fig)
        # insights = get_graph_insights(fig_data)
        # Convert figure to JSON for rendering in web applications
        plots["CO2 Emissions"] = make_serializable(fig.to_json())
        """{
            "plot": make_serializable(fig.to_json()),
            'insights': insights
        }"""
    except Exception as e:
        print(e)

    try:
        fig = px.violin(
            df,
            x="EquipID",
            y="Achievement%",
            box=True,
            points="all",
            title="Distribution of Achievement% by EquipID",
            color="EquipID"
        )
        fig_data = generate_gpt_insight_payload(fig)
        insights = get_graph_insights(fig_data)
        # Convert figure to JSON for rendering in web applications
        plots["Distribution of Achievement% by EquipID"] = make_serializable(fig.to_json())

        #     {
        #     "plot": make_serializable(fig.to_json()),
        #     'insights': insights
        # }
    except Exception as e:
        print(e)

    try:
        latest_achievement = df.iloc[-1]["Achievement%"]

        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=latest_achievement,
            title={'text': "Latest Achievement %"},
            delta={'reference': 100},
            gauge={
                'axis': {'range': [90, 110]},
                'bar': {'color': "green"},
                'steps': [
                    {'range': [90, 95], 'color': "lightgray"},
                    {'range': [95, 100], 'color': "gray"},
                    {'range': [100, 105], 'color': "lightgreen"},
                    {'range': [105, 110], 'color': "lime"},
                ]
            }
        ))
        # fig_data = generate_gpt_insight_payload(fig)
        # insights = get_graph_insights(fig_data)
        # # Convert figure to JSON for rendering in web applications
        plots["Latest Achievement"] = make_serializable(fig.to_json())
        # {
        #     "plot": make_serializable(fig.to_json()),
        #     'insights': insights
        # }
    except Exception as e:
        print(e)

    try:
        fig = go.Figure()

        for equip in df["EquipID"].unique():
            sub_df = df[df["EquipID"] == equip]
            fig.add_trace(go.Scatter(x=sub_df["Date"], y=sub_df["CO2 Emission - Actual"],
                                     mode='lines+markers', name=f'Equip {equip} - Actual'))
            fig.add_trace(go.Scatter(x=sub_df["Date"], y=sub_df["Target"],
                                     mode='lines', name=f'Equip {equip} - Target', line=dict(dash='dash')))

        fig.update_layout(title="Actual vs Target CO₂ Emissions", xaxis_title="Date", yaxis_title="CO₂ Emission")
        # fig_data = generate_gpt_insight_payload(fig)
        # insights = get_graph_insights(fig_data)
        # Convert figure to JSON for rendering in web applications
        plots["Actual vs Target CO₂ Emissions"] = make_serializable(fig.to_json())
        #     {
        #     "plot": make_serializable(fig.to_json()),
        #     'insights': insights
        # }
    except Exception as e:
        print(e)

    try:
        df["Alert"] = df["Achievement%"].apply(lambda x: "Good" if x >= 100 else "Underperforming")

        fig = px.scatter(df, x="Date", y="Achievement%", color="Alert", symbol="EquipID",
                         size="Deficit%", title="KPI Alert Monitor")
        # fig_data = generate_gpt_insight_payload(fig)
        # insights = get_graph_insights(fig_data)
        # Convert figure to JSON for rendering in web applications
        plots["KPI Alert Monitor"] = make_serializable(fig.to_json())
        #     {
        #     "plot": make_serializable(fig.to_json()),
        #     'insights': insights
        # }
    except Exception as e:
        print(e)

    try:
        fig = px.area(df, x="Date", y="CO2 Emission - Actual", color="EquipID",
                      title="Stacked CO₂ Emission Over Time by EquipID")
        fig_data = generate_gpt_insight_payload(fig)
        insights = get_graph_insights(fig_data)
        # Convert figure to JSON for rendering in web applications
        plots["Stacked CO₂ Emission Over Time by EquipID"] = make_serializable(fig.to_json())
        #     {
        #     'plot': make_serializable(fig.to_json()),
        #     'insights': insights
        # }
    except Exception as e:
        print(e)

    try:
        df["zscore"] = (df["CO2 Emission - Actual"] - df["CO2 Emission - Actual"].mean()) / df[
            "CO2 Emission - Actual"].std()
        df["Anomaly"] = df["zscore"].apply(lambda z: "Anomaly" if abs(z) > 2 else "Normal")

        fig = px.scatter(df, x="Date", y="CO2 Emission - Actual", color="Anomaly",
                         title="Anomaly Detection on CO₂ Emissions")
        # fig_data = generate_gpt_insight_payload(fig)
        # insights = get_graph_insights(fig_data)
        # Convert figure to JSON for rendering in web applications
        plots["Anomaly Detection on CO₂ Emissions"] = make_serializable(fig.to_json())
        #     {
        #     "plot": make_serializable(fig.to_json()),
        #     'insights': insights
        # }
    except Exception as e:
        print(e)

    return plots


def resample_data(df, freq):
    print(f"Resampling data to {freq} frequency")
    if freq == 'hours':
        return df.resample('H').mean().ffill()
    elif freq == 'days':
        return df.resample('D').mean().ffill()
    elif freq == 'weeks':
        return df.resample('W').mean().ffill()
    elif freq == 'months':
        return df.resample('M').mean().ffill()
    elif freq == 'years':
        return df.resample('A').mean().ffill()
    else:
        raise ValueError("Unsupported frequency")


# Check Trend using Augmented Dickey-Fuller Test
def detect_trend(df):
    print('Detecting Trend...')
    result = adfuller(df['value'])
    p_value = result[1]
    return p_value > 0.05  # If p-value > 0.05 → Trend exists


# Check Seasonality using autocorrelation
def detect_seasonality(df):
    print('Detecting Seasonality...')
    autocorr = df['value'].autocorr(lag=1)
    return abs(autocorr) > 0.3  # If autocorr > 0.3 → Seasonality exists


# Train ARIMA Model
def train_auto_arima(train, test):
    print('Training ARIMA...')
    try:
        m = pd.infer_freq(train.index)
        if m == '15T':
            m = 96
        elif m == '30T':
            m = 48
        elif m == 'H':
            m = 24
        elif m == 'D':
            m = 7
        elif m == 'W':
            m = 52
        elif m == 'M':
            m = 12
        elif m == 'Q':
            m = 4
        elif m == 'A' or (m and m.startswith('A-')):
            m = 1
        else:
            raise ValueError(f"Unsupported frequency '{m}'.")

        model = pm.auto_arima(train['value'],
                              m=m,
                              seasonal=True,
                              d=None,
                              test='adf',
                              start_p=0, start_q=0,
                              max_p=12, max_q=12,
                              D=None,
                              trace=True,
                              error_action='ignore',
                              suppress_warnings=True,
                              stepwise=True)

        pred = model.predict(n_periods=len(test))
        error = mean_squared_error(test['value'], pred, squared=False)  # RMSE
        return model, error
    except Exception as e:
        print(f"Auto-ARIMA Error: {e}")
        return None, float('inf')


def train_arima(train, test):
    model = ARIMA(train['value'], order=(1, 1, 1)).fit()
    pred = model.predict(start=test.index[0], end=test.index[-1])
    error = mean_squared_error(test['value'], pred, squared=False)
    return model, error


# Train Prophet Model
def train_prophet(train, test):
    print("Training Prophet...")
    prophet_df = train.reset_index().rename(columns={'datetime': 'ds', 'value': 'y'})
    model = Prophet()
    model.fit(prophet_df)

    future = pd.DataFrame({'ds': test.index})
    forecast = model.predict(future)
    error = mean_squared_error(test['value'], forecast['yhat'], squared=False)
    return model, error


# Train XGBoost Model
def train_xgboost(train, test):
    print("Training XGBoost...")
    X_train = np.arange(len(train)).reshape(-1, 1)
    y_train = train['value'].values
    X_test = np.arange(len(train), len(train) + len(test)).reshape(-1, 1)

    model = XGBRegressor(objective='reg:squarederror')
    model.fit(X_train, y_train)
    model.last_index_ = len(train) + len(test) - 1
    pred = model.predict(X_test)
    error = mean_squared_error(test['value'], pred, squared=False)
    return model, error


# Train RandomForest Model
def train_randomforest(train, test):
    print("Training RandomForest...")
    X_train = np.arange(len(train)).reshape(-1, 1)
    y_train = train['value'].values
    X_test = np.arange(len(train), len(train) + len(test)).reshape(-1, 1)

    model = RandomForestRegressor()
    model.fit(X_train, y_train)
    model.last_index_ = len(train) + len(test) - 1
    pred = model.predict(X_test)
    error = mean_squared_error(test['value'], pred, squared=False)
    return model, error


# Save the Best Model
def save_best_model(model, model_path):
    joblib.dump(model, model_path)


def train_models(df, target_col, user_id):
    frequencies = ['hours', 'days', 'weeks', 'months', 'years']
    for freq in frequencies:
        try:
            print(f"\nTraining {freq} models...")

            # Resample the data for each frequency
            resampled_df = resample_data(df, freq)
            train, test = train_test_split(resampled_df, test_size=0.2, shuffle=False)

            trend = detect_trend(train)
            seasonality = detect_seasonality(train)

            best_model = None
            best_error = float('inf')
            best_model_name = ""
            scenario = ""

            # Scenario 1: Trend only
            if trend and not seasonality:
                scenario = "Trend only"
                arima_model, arima_error = train_arima(train, test)
                xgb_model, xgb_error = train_xgboost(train, test)

                if arima_error < xgb_error:
                    best_model, best_error = arima_model, arima_error
                    best_model_name = "ARIMA"
                else:
                    best_model, best_error = xgb_model, xgb_error
                    best_model_name = "XGBoost"

            # Scenario 2: Seasonality only
            if seasonality and not trend:
                scenario = "Seasonality only"
                prophet_model, prophet_error = train_prophet(train, test)
                arima_model, arima_error = train_arima(train, test)

                if prophet_error < arima_error:
                    best_model, best_error = prophet_model, prophet_error
                    best_model_name = "Prophet"
                else:
                    best_model, best_error = arima_model, arima_error
                    best_model_name = "ARIMA"

            # Scenario 3: Trend + Seasonality
            if trend and seasonality:
                scenario = "Trend + Seasonality"
                prophet_model, prophet_error = train_prophet(train, test)
                arima_model, arima_error = train_arima(train, test)

                min_error = min(prophet_error, arima_error)
                if min_error == prophet_error:
                    best_model, best_error = prophet_model, prophet_error
                    best_model_name = "Prophet"
                elif min_error == arima_error:
                    best_model, best_error = arima_model, arima_error
                    best_model_name = "ARIMA"

            # Scenario 4: No Trend or Seasonality
            if not trend and not seasonality:
                scenario = "No trend or seasonality"
                xgb_model, xgb_error = train_xgboost(train, test)
                rf_model, rf_error = train_randomforest(train, test)

                if xgb_error < rf_error:
                    best_model, best_error = xgb_model, xgb_error
                    best_model_name = "XGBoost"
                else:
                    best_model, best_error = rf_model, rf_error
                    best_model_name = "RandomForest"

            # Save the best model
            if best_model:
                aws_s3_obj.upload_pickle(best_model, s3_cred["credentials"]['base_bucket_name'],
                                         f'{user_id}/output/models/Arima/{target_col}/{freq}/best_model.pkl')

                aws_s3_obj.upload_file_obj_to_s3(
                    {"scenario": scenario, "model_name": best_model_name},
                    s3_cred["credentials"]['base_bucket_name'],
                    f'{user_id}/output/models/Arima/{target_col}/{freq}/scenario_{freq}.json', 'json')

                print(f"\n{freq.capitalize()} Training complete. Scenario: {scenario}, Model: {best_model_name}")
        except Exception as e:
            print(e)


# Forecast
def arima_forecast(model, periods, freq, target_col, user_id):
    freq_map = {
        'hours': 'H',
        'days': 'D',
        'weeks': 'W',
        'months': 'M',
        'quarters': 'QS',
        'years': 'YS'
    }
    data = aws_s3_obj.download_file(s3_cred["credentials"]['base_bucket_name'],
                                    f'{user_id}/output/models/Arima/{target_col}/{target_col}_results.json', 'json')

    end_date = data.get('end_date')
    frequency = freq_map[data.get('data_freq').lower()]
    try:
        start_date = pd.to_datetime(end_date) + pd.tseries.frequencies.to_offset(frequency)
    except Exception as e:
        start_date = pd.to_datetime(end_date)

    future = pd.date_range(start=start_date, periods=periods, freq=freq)
    future = future.to_series().dt.date.tolist()

    model_type = str(type(model))
    print(f"Detected model type: {model_type}")

    try:
        if 'Prophet' in model_type:
            future_df = pd.DataFrame({'ds': future})
            # Prophet expects 'ds' column and returns 'yhat'
            forecast = model.predict(future_df)
            if 'yhat' in forecast.columns:
                forecast = forecast[['ds', 'yhat']]
                forecast['yhat'] = forecast['yhat'].round(2)
                forecast.columns = ['date', 'forecasted_value']
                return forecast
            else:
                raise ValueError("Prophet output missing 'yhat' column.")

        else:
            # ARIMA, XGBoost, RandomForest — Expect direct prediction
            future_df = pd.DataFrame({'date': future})  # Rename here
            if 'ARIMA' in model_type:
                forecast = model.forecast(steps=future_df.shape[0])
                future_df['forecasted_value'] = np.round(forecast.values, 2)
            else:
                start_idx = model.last_index_ + 1  # get from model
                end_idx = start_idx + len(future_df)
                X_future = np.arange(start_idx, end_idx).reshape(-1, 1)
                print(X_future)
                forecast = model.predict(X_future)
                future_df['forecasted_value'] = np.round(forecast, 2)

            return future_df[['date', 'forecasted_value']]

    except Exception as e:
        print(f"Prediction Error: {e}")


def check_data_frequency(train):
    data_freq = {'D': 'Days', 'W': 'Weeks', "H": "Hours", "Q": "Quarters", 'A': 'Years', "M": "Months", "MS": "Months",
                 'A-JAN': 'Years'}
    m = pd.infer_freq(train.index)
    if m in ['15T', '30T', "H", "D", "W", "M", "Q", "A", "MS", 'A-JAN']:
        return data_freq[m]
    else:
        return 'Unsupported frequency'


def summarize_csv(df):
    return f"""User uploaded a CSV with {df.shape[0]} rows and {df.shape[1]} columns.\n\n""" \
           f"Columns: {', '.join(df.columns)}\n\n" \
           f"Sample Rows:\n{df.head(5).to_string(index=False)}\n\n" \
           f"Column Summary:\n{df.describe(include='all').transpose().to_string()}"


def count_tokens(messages, model="gpt-4o-mini"):
    enc = tiktoken.encoding_for_model(model)
    total = 0
    for msg in messages:
        total += len(enc.encode(msg['content']))
    return total


# def get_or_create_user_session(user_id):
#     # ✅ Always return the latest session (general or CSV)
#     return ChatSession.objects.filter(user_id=user_id).order_by('-created_at').first() or ChatSession.objects.create(
#         user_id=user_id)


def summarize_text(text):
    summary_prompt = [
        {"role": "system", "content": "Summarize the following conversation briefly to preserve context."},
        {"role": "user", "content": text}
    ]
    try:
        summary_resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=summary_prompt,
            temperature=0.3,
            max_tokens=300
        )
        return summary_resp.choices[0].message.content
    except Exception as e:
        # On error, fallback to empty summary to avoid blocking
        return "Conversation summary not available."
