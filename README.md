安裝虛擬環境  
pip install virtualenv  
virtualenv -p python3.9 django_mysql  
django_mysql\Scripts\activate  
pip install -r django_mysql_requirements.txt  
cd myproject  

需先在settings.py內找到database並修改password  

資料庫遷移  
python manage.py makemigrations  
python manage.py migrate  

//執行  
python manage.py runserver  
//直接使用以下連結 cmd給的連結會跑掉  
http://localhost:8000/accounts/login/  
