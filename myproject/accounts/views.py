from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib import auth
from django.contrib import messages
from django.db import connection
from .models import Accounts, Member, Classes, Coach, Payments
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.hashers import check_password


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            # 查詢資料庫中的帳號
            account = Accounts.objects.filter(username=username).first()
            
            if account:
                # 驗證密碼
                if account.passwordhash == password:
                    # 根據角色導向不同頁面
                    if account.role == 'Member':
                        request.session['member_id'] = account.memberid.memberid  # 儲存會員ID到session
                        return redirect('member')
                    elif account.role == 'Coach':
                        request.session['coach_id'] = account.coachid.coachid   # 儲存教練ID到session
                        return redirect('coach')
                    else:
                        messages.error(request, "無效的角色")
                else:
                    messages.error(request, "密碼錯誤")
            else:
                messages.error(request, "帳號不存在")
            
        except Exception as e:
            print(f"Error: {str(e)}")
            messages.error(request, "登入請求發生錯誤，請稍後再試")
        
        return redirect('login')

    return render(request, 'accounts/login.html')


# @login_required
def member_view(request):
    member_id = request.session.get('member_id')

    if member_id:
        member = Member.objects.filter(memberid=member_id).first()
        if member:
            try:
                # 原生 SQL 查詢
                with connection.cursor() as cursor:
                    # 最熱門的課程
                    cursor.execute("""
                        SELECT classname, COUNT(classname) AS class_count
                        FROM classes
                        GROUP BY classname
                        ORDER BY class_count DESC
                        LIMIT 3
                    """)
                    top_classes = cursor.fetchall()

                    # 授課時數最多的教練
                    cursor.execute("""
                        SELECT c.coachname, SUM(cl.hours) AS total_hours
                        FROM classes cl
                        JOIN coach c ON cl.coachid = c.coachid
                        GROUP BY cl.coachid
                        ORDER BY total_hours DESC
                        LIMIT 3
                    """)
                    top_coaches = cursor.fetchall()

                    # 當前會員的課程及教練
                    cursor.execute("""
                        SELECT cl.classname, c.coachname
                        FROM classes cl
                        JOIN coach c ON cl.coachid = c.coachid
                        WHERE cl.memberid = %s
                    """, [member_id])
                    member_classes = cursor.fetchall()

                return render(request, 'accounts/member.html', {
                    'member': member,
                    'top_classes': top_classes,
                    'top_coaches': top_coaches,
                    'member_classes': member_classes,
                })
            except Exception as e:
                messages.error(request, f"查詢數據時發生錯誤：{e}")
                return redirect('login')
        else:
            messages.error(request, "無法找到會員信息")
    else:
        messages.error(request, "無法找到會員信息")

    return redirect('login')


# @login_required
def coach_view(request):
    coach_id = request.session.get('coach_id')

    if coach_id:
        coach = Coach.objects.filter(coachid=coach_id).first()
        if coach:
            try:
                with connection.cursor() as cursor:
                    # 查詢學生會籍到期日
                    cursor.execute("""
                        SELECT 
                            m.memberid,
                            m.name AS student_name,
                            m.membershiptype,
                            m.expirydate,
                            IF(m.expirydate BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 3 MONTH), '!', '') AS alert
                        FROM 
                            `classes` cl
                        JOIN 
                            `member` m ON cl.memberid = m.memberid
                        WHERE 
                            cl.coachid = %s
                            AND m.expirydate > CURDATE();
                    """, [coach_id])
                    student_expiry_dates = cursor.fetchall()

                    # 本月授課時數及課程分布
                    cursor.execute("""
                        SELECT 
                            cl.classname,
                            SUM(cl.hours) AS total_hours
                        FROM 
                            `classes` cl
                        WHERE 
                            cl.coachid = %s AND 
                            MONTH(cl.date) = MONTH(CURDATE()) AND 
                            YEAR(cl.date) = YEAR(CURDATE())
                        GROUP BY 
                            cl.classname;
                    """, [coach_id])
                    class_hours = cursor.fetchall()

                # 3. 查詢該教練的專長
                coach_specialty = coach.specialty

                return render(request, 'accounts/coach.html', {
                    'coach': coach,
                    'student_expiry_dates': student_expiry_dates,
                    'class_hours': class_hours,
                    'coach_specialty': coach_specialty,
                })
            except Exception as e:
                messages.error(request, f"查詢數據時發生錯誤：{e}")
                return redirect('login')
        else:
            messages.error(request, "無法找到教練信息")
    else:
        messages.error(request, "無法找到教練信息")

    return redirect('login')


# @login_required
def change_password_view(request):
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not request.user.check_password(old_password):
            messages.error(request, '舊密碼不正確')
            return redirect('change_password')

        if new_password != confirm_password:
            messages.error(request, '新密碼與確認密碼不一致')
            return redirect('change_password')

        request.user.set_password(new_password)
        request.user.save()
        update_session_auth_hash(request, request.user)  # 保持登錄狀態
        messages.success(request, '密碼已成功更改')
        return redirect('member')

    return render(request, 'change_password.html')

def logout_view(request):
    # 登出當前用戶
    logout(request)
    # 重定向到登入頁面
    return redirect('login')