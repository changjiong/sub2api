<template>
  <AppLayout>
    <div class="mx-auto max-w-5xl space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p class="text-sm text-gray-500 dark:text-gray-400">Observability attachment</p>
          <h1 class="mt-1 break-all text-xl font-semibold text-gray-900 dark:text-white">
            {{ attachmentId }}
          </h1>
        </div>

        <div class="flex items-center gap-2">
          <button type="button" class="btn btn-secondary" :disabled="!objectUrl || downloading" @click="download">
            {{ downloading ? 'Preparing…' : 'Download' }}
          </button>
          <button type="button" class="btn btn-secondary" @click="goBack">Back</button>
        </div>
      </div>

      <div class="card min-h-[360px] p-6">
        <div v-if="loading" class="flex min-h-[300px] items-center justify-center">
          <div class="flex flex-col items-center gap-3 text-sm text-gray-500 dark:text-gray-400">
            <div class="h-8 w-8 animate-spin rounded-full border-b-2 border-primary-600"></div>
            Loading attachment…
          </div>
        </div>

        <div v-else-if="errorMessage" class="flex min-h-[300px] flex-col items-center justify-center gap-3 text-center">
          <p class="text-sm font-medium text-red-600 dark:text-red-400">{{ errorMessage }}</p>
          <p class="max-w-xl text-xs text-gray-500 dark:text-gray-400">
            If this is a newly-created attachment, wait a few seconds and refresh. A queued or failed upload is not immediately previewable.
          </p>
          <button type="button" class="btn btn-primary" @click="loadAttachment">Retry</button>
        </div>

        <div v-else-if="objectUrl" class="flex min-h-[300px] items-center justify-center rounded-xl bg-gray-50 p-4 dark:bg-dark-900">
          <img
            v-if="isImage"
            :src="objectUrl"
            :alt="attachmentId"
            class="max-h-[70vh] max-w-full rounded-lg object-contain shadow-sm"
          />
          <iframe
            v-else-if="isPdf"
            :src="objectUrl"
            title="Attachment preview"
            class="h-[70vh] w-full rounded-lg border border-gray-200 dark:border-dark-700"
          />
          <div v-else class="space-y-3 text-center">
            <p class="text-sm text-gray-600 dark:text-gray-300">This file type does not have an inline preview.</p>
            <button type="button" class="btn btn-primary" :disabled="downloading" @click="download">
              Download file
            </button>
          </div>
        </div>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { apiClient } from '@/api/client'

const route = useRoute()
const router = useRouter()
const attachmentId = computed(() => String(route.params.id || ''))

const loading = ref(true)
const downloading = ref(false)
const errorMessage = ref('')
const objectUrl = ref('')
const contentType = ref('')
const filename = ref('')

const isImage = computed(() => contentType.value.toLowerCase().startsWith('image/'))
const isPdf = computed(() => contentType.value.toLowerCase() === 'application/pdf')

function revokeObjectUrl() {
  if (objectUrl.value) {
    URL.revokeObjectURL(objectUrl.value)
    objectUrl.value = ''
  }
}

function parseFilename(contentDisposition: string | undefined): string {
  if (!contentDisposition) return ''
  const encoded = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1]
  if (encoded) {
    try {
      return decodeURIComponent(encoded)
    } catch {
      return encoded
    }
  }
  return contentDisposition.match(/filename="?([^";]+)"?/i)?.[1] || ''
}

async function loadAttachment() {
  revokeObjectUrl()
  loading.value = true
  errorMessage.value = ''

  try {
    const response = await apiClient.get(
      `/admin/observability/attachments/${encodeURIComponent(attachmentId.value)}/preview`,
      { responseType: 'blob' }
    )
    const blob = response.data as Blob
    contentType.value = String(response.headers['content-type'] || blob.type || '')
    filename.value = parseFilename(String(response.headers['content-disposition'] || ''))
    objectUrl.value = URL.createObjectURL(blob)
  } catch (error: any) {
    if (error?.status === 401) {
      errorMessage.value = '登录状态已失效，请重新登录 Sub2API 管理员账号。'
    } else if (error?.status === 404) {
      errorMessage.value = '附件不存在，或异步上传尚未完成。'
    } else {
      errorMessage.value = error?.message || '附件加载失败。'
    }
  } finally {
    loading.value = false
  }
}

async function download() {
  if (!objectUrl.value || downloading.value) return
  downloading.value = true
  try {
    const link = document.createElement('a')
    link.href = objectUrl.value
    link.download = filename.value || attachmentId.value
    document.body.appendChild(link)
    link.click()
    link.remove()
  } finally {
    downloading.value = false
  }
}

function goBack() {
  if (window.history.length > 1) {
    router.back()
  } else {
    router.push('/admin/dashboard')
  }
}

onMounted(loadAttachment)
onBeforeUnmount(revokeObjectUrl)
</script>
