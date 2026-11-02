<?php

namespace App\Http\Controllers;

use App\Models\Ticket;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class TicketController extends Controller
{
    public function show(Request $request): JsonResponse
    {
        $uid = $request->user()->id;

        $ticket = Ticket::where('id', $request->route('id'))
            ->where('owner_id', $uid)
            ->firstOrFail();

        return response()->json($ticket->only([
            'id',
            'subject',
            'status',
            'updated_at',
        ]));
    }
}
