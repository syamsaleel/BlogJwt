from rest_framework import serializers
from .models import User,BlogPost, Comment
from rest_framework.validators import UniqueValidator
from rest_framework.exceptions import ValidationError

class RegisterSerializer(serializers.ModelSerializer):
    
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )

    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    is_admin = serializers.BooleanField(default=False, read_only=True)
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password','is_admin']
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'is_admin': {'read_only': True}
        }

    def validate(self, data):
        username = data['username']
        email = data['email']

        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError('Username already exists.')

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('Email already exists.')

        return data
    
    def create(self, validated_data):
        is_admin = validated_data.pop('is_admin', False)
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )

        user.set_password(validated_data['password'])
        user.is_admin = is_admin
        user.save()

        return user
    
class BlogPostSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlogPost
        fields = ('id', 'title', 'content','image', 'created_time', 'updated_time', 'author')
        #read_only_fields = ('id', 'created_time', 'updated_time', 'author')

    def validate_title(self, value):
        if len(value) < 2:
            raise serializers.ValidationError("Title must be at least 2 characters long.")
        return value
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['username']

class CommentSerializer(serializers.ModelSerializer):
    user=UserSerializer(read_only=True)
    class Meta:
        model = Comment
        fields = ('id', 'content', 'created_time', 'updated_time', 'user', 'blog_post')