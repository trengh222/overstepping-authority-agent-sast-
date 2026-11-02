<?php
// A1：Laravel 路由参数直接 find，无归属校验。
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\TicketController;

Route::get('/api/tickets/{id}', [TicketController::class, 'show']);
