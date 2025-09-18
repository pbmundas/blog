     layout: category
     title: Threat Investigation Posts
     category: threat-investigation
     permalink: /category/threat-investigation
     <h1>{{ page.title }}</h1>
<div class="post-list">
  {% for post in site.categories.threat-investigation %}
    <li>
      <h2 class="post-title"><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
      <p class="post-meta">{{ post.date | date: "%b %-d, %Y" }}</p>
      {{ post.excerpt | strip_html }}
    </li>
  {% endfor %}
</div>
     ---
     All posts on investigating cyber incidents.
