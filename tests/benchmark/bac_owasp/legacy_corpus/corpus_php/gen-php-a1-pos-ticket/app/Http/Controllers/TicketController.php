<?php

namespace App\Http\Controllers;

use App\Models\Ticket;

class TicketController
{
    public function show($id)
    {
        return response()->json(Ticket::find($id));
    }
}
