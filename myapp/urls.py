from django.urls import path
from .views import (BlogPostListView,BlogPostDetailView,RegisterAPIView,
                    CommentDetailView,CommentListView,AdminRegisterAPIView,
                    AdminBlogPostListView,AdminBlogPostDetailView,
                    AdminCommentListView,AdminCommentDetailView,
                    AdminLogoutView,UserLogoutView)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    
)

urlpatterns = [
    #USER
    path('registeruser/', RegisterAPIView.as_view(), name='register'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('user/logout/', UserLogoutView.as_view(), name='userlogout'),

    #BLOG
    path('blog-posts/', BlogPostListView.as_view(), name='blogpost-list'),
    path('blog-posts/<int:pk>/', BlogPostDetailView.as_view(), name='blogpost-detail'),
    
    #COMMENT
    path('blog-posts/<int:blog_post_id>/comments/', CommentListView.as_view(), name='comment-list'),
    path('comments/<int:pk>/', CommentDetailView.as_view(), name='comment-detail'),

    #ADMIN
    path('login/', TokenObtainPairView.as_view(), name='admin-login'),
    path('register/', AdminRegisterAPIView.as_view(), name='admin-register'),
    path('blog-posts/', AdminBlogPostListView.as_view(), name='admin-blogpost-list'),
    path('main/blog-posts/<int:pk>/', AdminBlogPostDetailView.as_view(), name='admin-blogpost-delete'),
    path('main/comments/', AdminCommentListView.as_view(), name='admin-comment-list'),
    path('main/comments/<int:pk>/', AdminCommentDetailView.as_view(), name='admin-comment-delete'),
    path('logout/', AdminLogoutView.as_view(), name='admin-logout'),



]