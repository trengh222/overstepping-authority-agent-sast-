<?php

use App\Http\Controllers\Admin\UserRoleController;
use Illuminate\Support\Facades\Route;

Route::put('/admin/users/{id}/role', [UserRoleController::class, 'update']);
