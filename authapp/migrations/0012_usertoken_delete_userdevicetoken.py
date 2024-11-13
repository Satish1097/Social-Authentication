# Generated by Django 5.0 on 2024-10-30 13:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapp', '0011_userdevicetoken'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('refresh_token', models.CharField(max_length=255, unique=True)),
                ('access_token', models.CharField(max_length=255, unique=True)),
            ],
        ),
        migrations.DeleteModel(
            name='UserDeviceToken',
        ),
    ]
