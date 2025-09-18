     layout: category
     title: Resources Posts
     category: resources
     permalink: /category/resources
     <h1>{{ page.title }}</h1>
<div class="post-list">
  {% for post in site.categories.resources %}
    <li>
      <h2 class="post-title"><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
      <p class="post-meta">{{ post.date | date: "%b %-d, %Y" }}</p>
      {{ post.excerpt | strip_html }}
    </li>
  {% endfor %}
</div>
     ---
     All posts with cybersecurity resources and tools.
