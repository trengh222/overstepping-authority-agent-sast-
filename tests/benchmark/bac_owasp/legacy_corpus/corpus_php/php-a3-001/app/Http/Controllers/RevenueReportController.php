<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\JsonResponse;

class RevenueReportController extends Controller
{
    public function index(): JsonResponse
    {
        $paidTotal = Order::query()->where('status', 'paid')->sum('total');
        $paidCount = Order::query()->where('status', 'paid')->count();

        return response()->json([
            'currency' => 'CNY',
            'paid_total' => $paidTotal,
            'paid_count' => $paidCount,
            'generated_at' => now()->toIso8601String(),
        ]);
    }
}
