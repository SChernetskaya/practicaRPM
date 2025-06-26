Инструкция по запуску (общее)

1. Создать и активировать виртуальное окружение 
2. Установить зависимости
3. Запустить

Команды:
python -m venv venv

venv\Scripts\activate

pip install -r requirements.txt

uvicorn main:app --reload
