<?php

namespace App\Http\Controllers;

use App\Models\FailedJob;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Artisan;

class JobRetryController extends Controller
{
    public function store(string $id): JsonResponse
    {
        $job = FailedJob::findOrFail($id);

        Artisan::call('queue:retry', ['id' => [$job->id]]);

        return response()->json([
            'id' => $job->id,
            'status' => 'queued',
        ]);
    }
}
