<?php

namespace App\Http\Controllers;

use App\Models\Message;

class MessageController
{
    public function show($id)
    {
        return response()->json(Message::find($id));
    }
}
