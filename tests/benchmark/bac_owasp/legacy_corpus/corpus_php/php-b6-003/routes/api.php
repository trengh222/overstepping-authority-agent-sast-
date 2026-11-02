<?php

use App\Http\Controllers\Admin\MemberController;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth:sanctum', 'admin'])->group(function () {
    Route::get('/admin/members', [MemberController::class, 'index']);
});
