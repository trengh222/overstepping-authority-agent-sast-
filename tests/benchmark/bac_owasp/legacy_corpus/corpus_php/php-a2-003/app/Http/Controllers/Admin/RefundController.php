<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Order;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class RefundController extends Controller
{
    public function store(Request $request, string $id): JsonResponse
    {
        if ($request->user()->role !== 'admin') {
            abort(403, 'Forbidden');
        }

        $order = Order::findOrFail($id);
        $order->refunded_at = now();
        $order->save();

        return response()->json([
            'id' => $order->id,
            'status' => 'refunded',
        ]);
    }
}
