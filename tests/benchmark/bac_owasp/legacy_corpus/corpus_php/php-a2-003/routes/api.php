<?php

use App\Http\Controllers\Admin\RefundController;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth:sanctum', 'admin'])->group(function () {
    Route::post('/admin/orders/{id}/refund', [RefundController::class, 'store']);
});
