<?php

use App\Http\Controllers\RevenueReportController;
use Illuminate\Support\Facades\Route;

Route::get('/api/reports/revenue', [RevenueReportController::class, 'index']);
