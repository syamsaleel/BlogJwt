from django.shortcuts import render
from .serializers import RegisterSerializer,BlogPostSerializer,CommentSerializer
from .models import BlogPost,Comment,User
from rest_framework.response import Response
from rest_framework import generics,permissions
from rest_framework import status
from rest_framework.permissions import IsAuthenticated , IsAdminUser,AllowAny,IsAuthenticatedOrReadOnly
from rest_framework.views import APIView
from django.core.mail import send_mail
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth import logout
from rest_framework.exceptions import PermissionDenied
from .permissions import IsAdminUserOrReadOnly
from django.views.decorators.csrf import csrf_exempt




class RegisterAPIView(APIView):
    def post(self, request, format=None):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            new_user = serializer.save()

            # Send welcome email to the newly registered user
            email_to = [new_user.email]
            subject = 'Welcome to Our Blogging Platform'
            message = f'Dear {new_user.first_name},\n\nThank you for registering on our Blogging Platform. We are excited to have you!\n\nStart sharing your thoughts and ideas by creating your first blog post.\n\nHappy blogging!\nThe Blogging Platform Team'
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, email_to)

            return Response({'message': 'User created.'}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



#class RegisterAPIView(generics.CreateAPIView):
#    serializer_class = RegisterSerializer
#    Permission_class=[AllowAny]
#    def post(self, request, *args, **kwargs):
#        response = super().post(request, *args, **kwargs)
#        if response.status_code == status.HTTP_201_CREATED:
#            send_registration_email(User)
#            return Response({'status': status.HTTP_201_CREATED, 
                             #'payload': response.data,
#                              'message': 'User created.'})
#        return Response({'status': status.HTTP_400_BAD_REQUEST, 'errors': response.data})
#    @receiver(post_save, sender=User)
#    def send_registration_email(sender, instance, created, **kwargs):
#        if created:
#            subject = 'Welcome to Our Blogging Platform'
#            message = f'Dear {instance.first_name},\n\nThank you for registering on our Blogging Platform. We are excited to have you!\n\nStart sharing your thoughts and ideas by creating your first blog post.\n\nHappy blogging!\n\nBest regards,\nThe Blogging Platform Team'
#            to_email = instance.email
#            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL,[to_email])

class BlogPostListView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        
        blog_posts = BlogPost.objects.all()
        serializer = BlogPostSerializer(blog_posts, many=True)
        return Response(serializer.data)

    def post(self, request):
        
        serializer = BlogPostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

class BlogPostDetailView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]
    authentication_classes = [JWTAuthentication]

    def get_object(self, pk):
        try:
            return BlogPost.objects.get(pk=pk)
        except BlogPost.DoesNotExist:
            return None

    def get(self, request, pk):
        
        blog_post = self.get_object(pk)
        if blog_post is not None:
            serializer = BlogPostSerializer(blog_post)
            return Response(serializer.data)
        return Response({"detail": "Blog post not found."}, status=404)

    def put(self, request, pk):
        
        blog_post = self.get_object(pk)
        if blog_post is not None:
            if request.user == blog_post.author:
                serializer = BlogPostSerializer(blog_post, data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data)
                return Response(serializer.errors, status=400)
            else:
                return Response({"detail": "You don't have permission to edit this blog post."}, status=403)
        return Response({"detail": "Blog post not found."}, status=404)

    def delete(self, request, pk):
       
        blog_post = self.get_object(pk)
        if blog_post is not None:
            if request.user == blog_post.author:
                blog_post.delete()
                return Response({"detail": "Blog post deleted successfully."}, status=204)
            else:
                return Response({"detail": "You don't have permission to delete this blog post."}, status=403)
        return Response({"detail": "Blog post not found."}, status=404)

class CommentListView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = CommentSerializer

    def get_queryset(self):
        blog_post_id = self.kwargs['blog_post_id']
        return Comment.objects.filter(blog_post_id=blog_post_id)
    
    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = CommentSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self, request, blog_post_id):
       
        try:
            blog_post = BlogPost.objects.get(pk=blog_post_id)
        except BlogPost.DoesNotExist:
            return Response({"detail": "Blog post not found."}, status=404)

        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user, blog_post=blog_post)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

class CommentDetailView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_object(self, pk):
        try:
            return Comment.objects.get(pk=pk)
        except Comment.DoesNotExist:
            return None
  
    def get(self, request, pk):
       
        comment = self.get_object(pk)
        if comment is not None:
            serializer = CommentSerializer(comment)
            return Response(serializer.data)
        return Response({"detail": "Comment not found."}, status=404)

    def put(self, request, pk):
       
        comment = self.get_object(pk)
        if comment is not None:
            if request.user == comment.user:
                serializer = CommentSerializer(comment, data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data)
                return Response(serializer.errors, status=400)
            else:
                return Response({"detail": "You don't have permission to edit this comment."}, status=403)
        return Response({"detail": "Comment not found."}, status=404)

    def delete(self, request, pk):
        
        comment = self.get_object(pk)
        if comment is not None:
            if request.user == comment.user:
                comment.delete()
                return Response({"detail": "Comment deleted successfully."}, status=204)
            else:
                return Response({"detail": "You don't have permission to delete this comment."}, status=403)
        return Response({"detail": "Comment not found."}, status=404)
    


class UserLogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({'message': 'User Logged out successfully'}, status=status.HTTP_200_OK)


#class  AdminLoginView(APIView):
#    def post(self, request):
#        email = request.data.get('email')  
#        password = request.data.get('password')
#        user = authenticate(email=email, password=password)

#        if user and user.is_admin:  
#            refresh = RefreshToken.for_user(user)
#            return Response({'access_token': str(refresh.access_token)}, status=status.HTTP_200_OK)
#        else:
#            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)





class AdminRegisterAPIView(APIView):
    serializer_class = RegisterSerializer
    permission_classes = [IsAuthenticated, IsAdminUserOrReadOnly]
    authentication_classes = [JWTAuthentication]

    def post(self, request, format=None):
        if not request.user.is_admin:
            raise PermissionDenied(detail="You do not have permission to access this resource.")

        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            new_admin = serializer.save()

            # Additional logic for admin registration
            new_admin.is_admin = True
            new_admin.save()

            return Response({'message': 'Admin created.'}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminBlogPostListView(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = BlogPost.objects.all()
    serializer_class = BlogPostSerializer
    permission_classes = [IsAuthenticated, IsAdminUserOrReadOnly]

class AdminBlogPostDetailView(generics.RetrieveDestroyAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = BlogPost.objects.all()
    serializer_class = BlogPostSerializer
    permission_classes = [IsAuthenticated, IsAdminUserOrReadOnly]

class AdminCommentListView(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated, IsAdminUserOrReadOnly]

class AdminCommentDetailView(generics.RetrieveDestroyAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated, IsAdminUserOrReadOnly]


class AdminLogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)