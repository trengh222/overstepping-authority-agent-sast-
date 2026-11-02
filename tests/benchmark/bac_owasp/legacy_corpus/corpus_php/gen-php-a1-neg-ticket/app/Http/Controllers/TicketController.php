<?php

namespace App\Http\Controllers;

use App\Models\Ticket;
use Illuminate\Support\Facades\Auth;

class TicketController
{
    public function show($id)
    {
        $uid = Auth::id();
        $item = Ticket::where('id', $id)->where('user_id', $uid)->firstOrFail();
        return response()->json($item);
    }
}
