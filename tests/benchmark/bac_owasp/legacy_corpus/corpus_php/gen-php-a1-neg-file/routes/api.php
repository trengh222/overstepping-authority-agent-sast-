<?php
// A1 负例：Laravel 路由带 auth 中间件，且查询限定 user_id。
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\FileRecordController;

Route::get('/api/files/{id}', [FileRecordController::class, 'show'])->middleware('auth');
