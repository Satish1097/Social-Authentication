# Generated by Django 5.0 on 2024-11-12 12:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapp', '0012_usertoken_delete_userdevicetoken'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='email',
            field=models.EmailField(blank=True, max_length=254),
        ),
        migrations.AlterField(
            model_name='otp',
            name='mobile',
            field=models.CharField(blank=True, max_length=13),
        ),
    ]