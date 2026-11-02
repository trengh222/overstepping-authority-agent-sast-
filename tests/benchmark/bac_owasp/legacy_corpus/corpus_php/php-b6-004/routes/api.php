<?php

use App\Http\Controllers\TicketController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/api/tickets/{id}', [TicketController::class, 'show']);
});
