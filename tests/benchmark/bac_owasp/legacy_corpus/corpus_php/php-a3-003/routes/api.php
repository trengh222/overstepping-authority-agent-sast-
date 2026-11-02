<?php

use App\Http\Controllers\JobRetryController;
use Illuminate\Support\Facades\Route;

Route::post('/internal/jobs/{id}/retry', [JobRetryController::class, 'store']);
