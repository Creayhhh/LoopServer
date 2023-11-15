# LoopServer
Loop健身系统的服务端

## 对于WEB后台管理系统暴露的接口
登录：/admin/login
注册：/admin/register
登出：/admin/logout
检查是否登录：/admin/checkLogged
注册用户：/admin/registerUser
获取所有用户：/admin/getUsers
获取用户所有信息：/admin/getUserAllInfo
获取用户所有运动记录：/admin/getUsersSportHistory

## 对于健身系统暴露的接口
登录：/user/login
提交运动记录：/user/submit/record
查询该用户的信息：/user/query/userinfo
查询该用户的运动记录：/user/query/history
刷新token：/user/token/refresh
