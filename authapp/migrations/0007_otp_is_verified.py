# Generated by Django 5.0 on 2024-10-26 11:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapp', '0006_alter_user_email'),
    ]

    operations = [
        migrations.AddField(
            model_name='otp',
            name='is_verified',
            field=models.BooleanField(default=True),
        ),
    ]
