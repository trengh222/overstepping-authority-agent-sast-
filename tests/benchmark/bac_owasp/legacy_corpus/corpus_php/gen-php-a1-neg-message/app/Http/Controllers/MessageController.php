<?php

namespace App\Http\Controllers;

use App\Models\Message;
use Illuminate\Support\Facades\Auth;

class MessageController
{
    public function show($id)
    {
        $uid = Auth::id();
        $item = Message::where('id', $id)->where('user_id', $uid)->firstOrFail();
        return response()->json($item);
    }
}
