<?php

use App\Http\Controllers\SettingsController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->get('/api/settings', [SettingsController::class, 'show']);
