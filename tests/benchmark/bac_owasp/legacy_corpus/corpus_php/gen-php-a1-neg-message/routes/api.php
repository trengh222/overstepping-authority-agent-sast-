<?php
// A1 负例：Laravel 路由带 auth 中间件，且查询限定 user_id。
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\MessageController;

Route::get('/api/messages/{id}', [MessageController::class, 'show'])->middleware('auth');
