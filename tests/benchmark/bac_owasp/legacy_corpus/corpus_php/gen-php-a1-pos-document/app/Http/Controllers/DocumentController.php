<?php

namespace App\Http\Controllers;

use App\Models\Document;

class DocumentController
{
    public function show($id)
    {
        return response()->json(Document::find($id));
    }
}
